<?php

// Regression tests for the security fixes of the maintenance branch.
class SecurityFunctionsTest extends RTTestCase
{
	/**
	 * @group small
	 * @dataProvider providerDeviceArgs
	 */
	public function testNoControlCharsInDeviceArgs ($arg, $is_valid)
	{
		if (! $is_valid)
			$this->expectException ('RTGatewayError');
		assertNoControlChars (array ('opcode' => 'getportmaclist', 'arg1' => $arg));
		$this->assertTrue ($is_valid);
	}

	public function providerDeviceArgs ()
	{
		return array
		(
			array ('Gi0/1', TRUE),
			array ("Gi0/1\tdescr", TRUE),
			array ("Gi0/1\nconfigure terminal", FALSE),
			array ("Gi0/1\rend", FALSE),
			array ("Gi0/1\x00", FALSE),
		);
	}

	/**
	 * @group small
	 * @dataProvider providerPortNames
	 */
	public function testPortName ($name, $is_valid)
	{
		if (! $is_valid)
			$this->expectException ('InvalidArgException');
		assertValidPortName ($name);
		$this->assertTrue ($is_valid);
	}

	public function providerPortNames ()
	{
		return array
		(
			array ('Gi0/1', TRUE),
			array ('eth0.100', TRUE),
			array ("Gi0/1\nwrite memory", FALSE),
			array ("Gi0/1\tx", FALSE),
		);
	}

	/**
	 * @group small
	 * @dataProvider providerHostnames
	 */
	public function testGatewayHostname ($hostname, $is_valid)
	{
		if (! $is_valid)
			$this->expectException ('RTGatewayError');
		$params = makeGatewayParams (0, array (array ('protocol' => 'ssh', 'hostname' => $hostname)), array (''));
		$this->assertContains ($hostname, $params);
		$this->assertNotContains ('-oStrictHostKeyChecking=no', $params);
	}

	public function providerHostnames ()
	{
		return array
		(
			array ('sw1.example.net', TRUE),
			array ('192.0.2.1', TRUE),
			array ('2001:db8::1', TRUE),
			array ('-oProxyCommand=touch /tmp/x', FALSE),
			array ('sw1 -oProxyCommand=x', FALSE),
			array ("sw1\n", FALSE),
		);
	}

	/**
	 * @group small
	 */
	public function testSSHNoKeyCredentialsNotOnCommandLine ()
	{
		$settings = array ('protocol' => 'sshnokey', 'hostname' => 'sw1', 'username' => 'u', 'password' => 'secret');
		$commands = "show version\n";
		$params = makeGatewayParams (0, array (&$settings), array (&$commands));
		$this->assertNotContains ('secret', $params);
		$this->assertStringStartsWith ("u\nsecret\n", $commands);
	}

	/**
	 * @group small
	 * @dataProvider providerHrefs
	 */
	public function testSafeHref ($url, $expected)
	{
		$this->assertSame ($expected, safeHref ($url));
	}

	public function providerHrefs ()
	{
		return array
		(
			array ('https://example.com/a?b=1&c=2', 'https://example.com/a?b=1&amp;c=2'),
			array ('index.php?page=depot', 'index.php?page=depot'),
			array ('javascript:alert(1)', '#'),
			array (' JavaScript:alert(1)', '#'),
			array ('data:text/html,<script>', '#'),
			array ("x' onmouseover='alert(1)", 'x&#039; onmouseover=&#039;alert(1)'),
		);
	}

	/**
	 * @group small
	 */
	public function testCSRFTokenInForms ()
	{
		global $pageno, $tabno;
		$pageno = 'index';
		$tabno = 'default';
		ob_start();
		printOpFormIntro ('someOp', array ('x' => '"><script>'));
		$html = ob_get_clean();
		$this->assertStringContainsString ('name="csrf_token" value="' . getCSRFToken() . '"', $html);
		$this->assertStringNotContainsString ('"><script>', $html);
		$this->assertStringContainsString ('csrf_token=', makeHrefProcess (array ('page' => 'object', 'tab' => 'default', 'op' => 'someOp')));
	}

	/**
	 * @group small
	 */
	public function testSqlLikeSubstring ()
	{
		$this->assertEquals ('%abc%', sqlLikeSubstring ('abc'));
		$this->assertEquals ('%10\\%\\_a\\\\b%', sqlLikeSubstring ('10%_a\\b'));
	}
}
