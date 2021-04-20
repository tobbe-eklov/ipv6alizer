$('document').ready(function() {
	$('#bShare').click(function() {
		$('#share').val(window.location.protocol + "//" + window.location.host + "?address=" + ($('#checkboxUseHttps').is(":checked") ? "https://" : "http://") + $('#address').val().replace("http://", "").replace("https://", ""));
	});
    
	$('#bMtu').click(function() {
		RunTest();
	});
    	$('#address').on("keypress", function(e) {
		if (e.keyCode == 13) {
			RunTest();
			return false; // prevent the button click from happening
		}
	});
	$('#button-tweet').click(function() {
		$.ajax({
			url: "Controller2.php",
			type: "POST",
			data: {
				'action': 'tweet',
				'address': decodeURI($('#address').val()),
				'https': $('#checkboxUseHttps').is(":checked")
			}
		}).done(function(result) {
			showTwitterModal(result);
		}).fail(function(xhr, status, error) {
			showTwitterModal(error);
		});
	});
});

$(function() {
	var address = decodeURI(getParam("address"));
	if (address != 'undefined' && address != null) {
		var parts = address.split("://");
		$('#share').val("");
		$('#result-container').html("");
		if (parts.length == 2) {
			$('#address').val(parts[1].split(';')[0]);
			if (parts[0] == "http") {
				$("#checkboxUseHttps").prop('checked', false);
			} else if (parts[0] == "https") {
				$("#checkboxUseHttps").prop('checked', true);
			}
		}
		$.ajax({
			url: "Controller2.php",
			type: "POST",
			data: {
				'action': 'report',
				'address': address
			}
		}).done(function(result) {
			$('#terminal').html("");
			$('#result').html("");
			var rows = null;
			if (result) {
				try {
					var resultData = jQuery.parseJSON(result);
					rows = resultData.rows;
				} catch (ex) {
					console.log(ex);
				}
				if (rows) {
					for (i = 0; i < rows.length; i++) {
						terminalOut(rows[i].message, 0, rows[i].type);
						//console.log(rows[i].message);
					}
					terminalOut("<div class='cursor'></div>", 0);
					$('#share-container').removeClass('share-container-hide').addClass('share-container-hide');
					setResultMessage(resultData.label);
					//$('.nav-tabs a[href="#resultTab"]').tab('show');
				} else {
					terminalOut("<div class='cursor'></div>", 0);
				}
			} else {
				terminalOut("Test failed. Unable to read result data.", 0);
				terminalOut("<div class='cursor'></div>", 0);
			}
		}).fail(function(xhr, status, error) {
			$('#terminal').html("<p>&nbsp;Operation canceled. Server returned: " + xhr.status + "</p>");
		});
	}
});

function RunTest() {
	$('#bMtu').html('<div class="loader"></div>');
	$('#terminal').html("<p>Running. Please wait...</p><div class='cursor'></div>");
	$('#share').val("");
	$('#share-container').removeClass('share-container-hide').addClass('share-container-hide');
	$('.nav-tabs a[href="#outputTab"]').tab('show');
	$('#result-container').html("");
	$.ajax({
		url: "Controller2.php",
		type: "POST",
		data: {
			'action': 'MaximumTransmissionUnitTest',
			'address': decodeURI($('#address').val()),
			'https': $('#checkboxUseHttps').is(":checked")
		}
	}).done(function(result) {
		$('#terminal').html("");
		$('#result').html("");
		var rows = null;
		if (result) {
			try {
				var resultData = jQuery.parseJSON(result);
				rows = resultData.rows;
			} catch (ex) {
				console.log(ex);
				//console.log(JSON.stringify(result));
			}
			if (rows) {
				for (i = 0; i < rows.length; i++) {
					terminalOut(rows[i].message, i, rows[i].type);
					//console.log(rows[i].message);
				}
				terminalOut("<div class='cursor'></div>", (rows.length + 1) * 1000, '');
				setTimeout(resetSearchButton, (rows.length + 1) * 1000);
				if (resultData.success) {
					setResultMessageDelayed(resultData.label, (rows.length + 1) * 1000);
					setTimeout(shareLink, (rows.length + 1) * 1000);
					//setTimeout(showResultTab, (rows.length + 1)*1000);
				}
			} else {
				terminalOut("<div class='cursor'></div>", 0, '');
				setTimeout(resetSearchButton, 0);
			}
		} else {
			terminalOut("Test failed. Unable to read result data.", 0, '');
			terminalOut("<div class='cursor'></div>", 1000, '');
			setTimeout(resetSearchButton, 1000);
		}
	}).fail(function(xhr, status, error) {
		$('#terminal').html("<p>&nbsp;Operation canceled. Server returned: " + xhr.status + "</p>");
		setTimeout(resetSearchButton, 0);
	});
}

function terminalOut(text, delay, typestring) {
	setTimeout(function() {
		if (typestring == "WARNING" || typestring == "ERROR") {
			//$('#result').append("<h4>"+text+"</h4>");
			$('#terminal').append("<p><span class='terminal-warning'>" + text + "</span></p>");
		} else if (typestring == "NOTICE") {
			$('#terminal').append("<p><span class='terminal-notice'>" + text + "</span></p>");
		} else if (typestring == "LOG") {
			$('#terminal').append("<p><span class='terminal-log'>" + text + "</span></p");
		} else {
			if (text.indexOf("tcp-noconn") !== -1 || text.indexOf("pmtud-error") !== -1 || text.indexOf("pmtud-toobig") !== -1 || text.indexOf("pmtud-toosmall") !== -1 || text.indexOf("pmtud-fail") !== -1) {
				$('#terminal').append("<p><span class='terminal-warning'>" + text + "</span></p>");
			} else {
				$('#terminal').append("<p>" + text + "<br /></p>");
			}
		}
	}, 1000 * delay);
}

function setResultMessage(resultDescription) {
	$('#result-container').removeClass();
	if (resultDescription == "pmtud-toosmall" || resultDescription == "pmtud-toobig" || resultDescription == 'pmtud-error' || resultDescription == 'tcp-noconn' || resultDescription == 'pmtud-fail') {
		$('#result-container').addClass('result-container-red');
		$('#result-container').html("<label><h2>Test finished, result: " + resultDescription + "</h2></label>");
		showResultTab();
	} else if (resultDescription == "pmtud-success") {
		$('#result-container').addClass('result-container-green');
		$('#result-container').html("<label><h2>Test finished, result: " + resultDescription + "</h2></label>");
		showResultTab();
	} else {
		$('#result-container').addClass('result-container-white');
		$('#result-container').html("<label><h2>Test finished, result: " + resultDescription + "</h2></label>");
	}
}

function setResultMessageDelayed(resultDescription, delay) {
	setTimeout(function() {
		$('#result-container').removeClass();
		if (resultDescription == "pmtud-toosmall" || resultDescription == "pmtud-toobig" || resultDescription == 'pmtud-error' || resultDescription == 'tcp-noconn' || resultDescription == 'pmtud-fail') {
			$('#result-container').addClass('result-container-red');
			$('#result-container').html("<label><h2>Test finished, result: " + resultDescription + "</h2></label>");
			showResultTab();
		} else if (resultDescription == "pmtud-success") {
			$('#result-container').addClass('result-container-green');
			$('#result-container').html("<label><h2>Test finished, result: " + resultDescription + "</h2></label>");
			showResultTab();
		} else {
			$('#result-container').addClass('result-container-white');
			$('#result-container').html("<label><h2>Test finished, result: " + resultDescription + "</h2></label>");
		}
	}, delay);
}

function getParam(sParam) {
	var sPageURL = window.location.search.substring(1);
	var sURLVariables = sPageURL.split('?');
	for (var i = 0; i < sURLVariables.length; i++) {
		var sParameterName = sURLVariables[i].split('=');
		if (sParameterName[0] == sParam) {
			return sParameterName[1];
		}
	}
}

function resetSearchButton() {
	$('#bMtu').html('Check');
}

function shareLink() {
	var address = $('#address').val().replace("http://", "").replace("https://", "");
	if (address) {
		$('#share').val(window.location.protocol + "//" + window.location.host + "?address=" + ($('#checkboxUseHttps').is(":checked") ? "https://" : "http://") + address);
		$('#share-container').removeClass('share-container-hide').addClass('share-container-show');
	}
}

function showResultTab() {
	$('.nav-tabs a[href="#resultTab"]').tab('show');
}

function showTwitterModal(tweetText) {
	$('.modal-body').text(tweetText);
	$('#twitterModal').modal('show');
}
function hideTwitterModal() {
	console.log('click');
	$('#twitterModal').css('opacity', '0');
}
