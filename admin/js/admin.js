//Default Apps Filter
function mooauth_client_default_apps_input_filter() {
    var input, filter, ul, li, a, i;
    var counter = 0;
    input = document.getElementById("mo_oauth_client_default_apps_input");
    filter = input.value.toUpperCase();
    ul = document.getElementById("mo_oauth_client_searchable_apps");
    li = ul.getElementsByTagName("li");
    for (i = 0; i < li.length; i++) {
        a = li[i].getElementsByTagName("a")[0];
        if (a.innerHTML.split('<br>')[1].toUpperCase().indexOf(filter) > -1) {
            li[i].style.display = "";
        } else {
            li[i].style.display = "none";
            counter++;
        }
        if(counter>=li.length) {
            document.getElementById("mo_oauth_client_search_res").innerHTML = "<p class='lead muted mo_premium_features_notice'>No applications found in this category, matching your search query. Please select a custom application from below.</p>";
        } else {
            document.getElementById("mo_oauth_client_search_res").innerHTML = "";
        }
    }
}

function mooauth_updateFormAction() {
	var appName = jQuery("#mo_oauth_custom_app_name").val();
	var action = jQuery("#form-common").attr("action");
	action = mooauth_UpdateUrlParam(action, "app", appName);
	jQuery("#form-common").attr("action", action);
}

function mooauth_UpdateUrlParam(url, param, updatedValue) {
	var parts = url.split("?");
	var base = parts[0];
	var params = mooauth_GetParams(parts[1]);
	params["action"] = "update";
	params[param] = updatedValue;
	var params = mooauth_ParseQS(params);
	console.log(params);
	return base + "?" + params;
}

function mooauth_ParseQS(params) {
	var qs = "";
	count = Object.keys(params).length;
	Object.keys(params).forEach(function(key) {
		count--;
		qs += key + "=" + params[key];
		if(count > 0) {
			qs += "&";
		}
	});
	return qs;
}

function mooauth_GetParams(queryString) {
	var pairs = queryString.split("&");
	var newPairs = {};
	for(var i = 0; i < pairs.length; i++) {
		var items = pairs[i].split("=");
		newPairs[items[0]] = items[1];
	}
	return newPairs;
}

function mooauth_outFunc() {
	var tooltip = document.getElementById("moTooltip");
	tooltip.innerHTML = "Copy to clipboard";
}

function mooauth_copyUrl() {
    var copyText = document.getElementById("callbackurl");
	mooauth_outFunc();
	copyText.select();
	copyText.setSelectionRange(0, 99999); 
	document.execCommand("copy");
	var tooltip = document.getElementById("moTooltip");
	tooltip.innerHTML = "Copied";
    // document.getElementById("redirect_url_change_warning").style.display = "none";
} 

function mooauth_showClientSecret(){
	var field = document.getElementById("mo_oauth_client_secret");
	var show_button = document.getElementById("show_button");
	if(field.type == "password"){
		field.type = "text";
		show_button.className = "fa fa-eye-slash";
	}
	else{
		field.type = "password";
		show_button.className = "fa fa-eye";
	}
}
