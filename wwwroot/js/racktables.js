// JavaScript functions

// Used for (un)checking an entire row of rackspace atoms
function toggleRowOfAtoms (rackId, rowId) {
	var toSet;
	var element;
	toSet = null;
	for (var columnId=0; columnId<=2; columnId++) {
		element = document.getElementById("atom_" + rackId + "_" + rowId + "_" + columnId);
		if (element != null && ! element.disabled) {
			if (toSet == null)
				toSet = !element.checked;
			element.checked = toSet;
		}
	}
}

// Used for (un)checking an entire column of rackspace atoms
function toggleColumnOfAtoms (rackId, columnId, numRows) {
	var toSet;
	var element;
	toSet = null;
	for (var rowId=1; rowId<numRows+1; rowId++) {
		element = document.getElementById("atom_" + rackId + "_" + rowId + "_" + columnId);
		if (element != null && ! element.disabled) {
			if (toSet == null)
				toSet = !element.checked;
			element.checked = toSet;
		}
	}
}

// Unchecks all checkboxes in the specified rack.
function uncheckAllAtoms (rackId, numRows) {
	var element;
	for (var rowId=1; rowId<numRows+1; rowId++) {
		for (var columnId=0; columnId<=2; columnId++) {
			element = document.getElementById("atom_" + rackId + "_" + rowId + "_" + columnId);
			if (element != null && ! element.disabled)
				element.checked = false;
		}
	}
}

// used by portinfo.js
function getQueryString(key, default_)
{
	if (default_==null) default_="";
	key = key.replace(/[\[]/,"\\\[").replace(/[\]]/,"\\\]");
	var regex = new RegExp("[\\?&]"+key+"=([^&#]*)");
	var qs = regex.exec(window.location.href);
	if(qs == null)
		return default_;
	else
		return qs[1];
}

// The pages declare their event handlers with data attributes instead of
// inline JavaScript, which the Content-Security-Policy forbids:
// data-rt-click (or data-rt-change, data-rt-submit) names a global function,
// data-rt-args holds its arguments as a JSON array. The function runs with
// "this" set to the element and gets the event as its last argument. The
// default action is cancelled for links and when the function returns false.
function rtDispatchEvent (e)
{
	var fn = window[this.getAttribute ('data-rt-' + e.type)];
	if (typeof fn !== 'function')
		return;
	var args = JSON.parse (this.getAttribute ('data-rt-args') || '[]');
	args.push (e);
	if (fn.apply (this, args) === false || (e.type == 'click' && this.tagName == 'A'))
		e.preventDefault();
}

// Pop-up windows hand the selected value over to the window that opened them.
function rtPopupOpenerLocation (base_url, select_id)
{
	var value = document.getElementById (select_id).value;
	if (value != '')
	{
		opener.location = base_url + encodeURIComponent (value);
		window.close();
	}
	return false;
}

function rtPopupOpenerField (field_id, select_id)
{
	var value = document.getElementById (select_id).value;
	if (value != '')
	{
		opener.document.getElementById (field_id).value = value;
		window.close();
	}
	return false;
}

// Open the URL of a pop-up link in a new window.
function rtOpenPopup (href, name, features)
{
	window.open (href, name, features);
}

function rtSubmitForm (name)
{
	document.getElementsByName (name)[0].submit();
}

// Give a select the CSS class of its selected option.
function rtCopySelectedClass ()
{
	this.className = this.options[this.selectedIndex].className;
}

$(document).on ('click', '[data-rt-click]', rtDispatchEvent);
$(document).on ('change', '[data-rt-change]', rtDispatchEvent);
$(document).on ('submit', '[data-rt-submit]', rtDispatchEvent);
$(document).on ('click', 'a.noclick', function (e) { e.preventDefault(); });
$(document).on ('click', 'a.need-confirmation', function (e) {
	if (! confirm ('Are you sure?'))
		e.preventDefault();
});