$(document).ready (function () {
	$('div.net-usage.pending').on('click', function(e) {
		var div = this;
		$.get(
			'index.php',
			{
				module: 'ajax',
				ac: 'net-usage',
				net_id: div.id
			},
			function (data, textStatus, jqXHR) {
				$(div)
					.removeClass('pending')
					.off(e)
					.replaceWith(data);
			}
		)
	});
});
