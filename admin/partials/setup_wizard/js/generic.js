
if(mo_oauth_ajax_object.app){
    var app = JSON.parse(mo_oauth_ajax_object.app);
    // console.log(app);
}
var last_step = 6;
var final_step = 5;
var mo_oauth_test_ajax_count = 0;
function mooauth_client_default_apps_input_filter() {
    var input, filter, ul, li, a, i;
    var counter = 0;
    input = document.getElementById("mo_oauth_client_default_apps_search");
    filter = input.value.toUpperCase();
    ul = document.getElementById("mo_oauth_client_searchable_apps");
    li = ul.getElementsByTagName("li");
    for (i = 0; i < li.length; i++) {
        a = li[i].getElementsByTagName("a")[0];
        if (undefined != a && a.innerHTML.split('<br>')[1].toUpperCase().indexOf(filter) > -1) {
            li[i].style.display = "";
        } else {
            li[i].style.display = "none";
            counter++;
        }
        if(counter>=li.length) {
            document.getElementById("mo_oauth_client_search_res").innerHTML = "<p class='lead muted mo_premium_features_notice'>It looks like your identity provider is not listed below, you can select Custom OAuth 2.0 or OpenID to configure the plugin. Please send us query using support form given aside for more details.</p>";
            li[1].style.display = "";
            li[2].style.display = "";
            li[3].style.display = "";
        } else {
            document.getElementById("mo_oauth_client_search_res").innerHTML = "";
        }
    }
}

/**
 * calls on refresh, reload, continue setup to fill setup wizard fields with previously saved app data
 */
function mooauth_auto_fill_form(){
   
    if (null != app && (null != app.mo_oauth_appId || undefined != app.mo_oauth_appId )) {
         mooauth_get_step(app.mo_oauth_step);
        jQuery("#appId").val(app.mo_oauth_appId);        
        jQuery("#displayName").val(app.mo_oauth_app_name);
        jQuery("#moauth_show_desc").html("This will displayed on SSO login button as<b> \"Login with " +app.mo_oauth_app_name +"\"</b>");
        if( undefined != app.mo_oauth_scopes_list && "" != app.mo_oauth_scopes_list){
            if(!Array.isArray(app.mo_oauth_scopes_list))
                  var scope_list = JSON.parse(app.mo_oauth_scopes_list);
            else
                var scope_list = app.mo_oauth_scopes_list;

            jQuery(".ui.fluid.dropdown").dropdown({values:scope_list});
            jQuery("#scope_list").val(app.mo_oauth_scopes_list);
        }else{
            jQuery(".ui.fluid.dropdown").dropdown({values:[]});
            jQuery("#scope_list").val("");
        }
        if(undefined != app.mo_oauth_scopes && "" != app.mo_oauth_scopes && "[\"\"]" != app.mo_oauth_scopes){
            console.log("on load");
            console.log(app.mo_oauth_scopes);
            if(!Array.isArray(app.mo_oauth_scopes))
                var scopes = JSON.parse(app.mo_oauth_scopes);
            else
                var scopes = app.mo_oauth_scopes;
            console.log("after parse");
            console.log(app.mo_oauth_scopes);            
            jQuery(".ui.dropdown.fluid").dropdown({allowAdditions: true,clearable:true});
            jQuery(".ui.fluid.dropdown").dropdown("clear");
            jQuery(".ui.fluid.dropdown").dropdown("set selected",scopes);
        }else{
            jQuery(".ui.dropdown.fluid").dropdown({allowAdditions: true,clearable:true});
        }
        if(undefined != app.mo_oauth_client_id)
            jQuery("#clientId").val(app.mo_oauth_client_id);
        if(undefined != app.mo_oauth_client_secret)
            jQuery("#clientSecret").val(app.mo_oauth_client_secret);
        var discovery = jQuery(".mo-discovery");
        jQuery(discovery).empty();
        if(undefined != app.mo_oauth_authorize)
            jQuery(discovery).append('<div class="field-group"><label>Authorization Endpoint</label><input type="text" class="mo-normal-text long-field" name="authorize" id="authorize" value="'+app.mo_oauth_authorize+'" placeholder="Enter authorization endpoint"></div>');
        if(undefined != app.mo_oauth_token)      
            jQuery(discovery).append('<div class="field-group"><label>Token Endpoint</label><input type="text" class="mo-normal-text long-field" name="token" id="token" value="'+app.mo_oauth_token+'" placeholder="Enter token endpoint"></div>');    
        if(undefined != app.mo_oauth_userinfo)
            jQuery(discovery).append('<div class="field-group"><label>Userinfo Endpoint</label><input type="text" class="mo-normal-text long-field" name="userinfo" id="userinfo" value="'+app.mo_oauth_userinfo+'" placeholder="Enter userinfo endpoint"></div>');
        if(undefined != app.mo_oauth_requesturl)
            jQuery(discovery).append('<div class="field-group"><label>Request Token Endpoint</label><input type="text" class="mo-normal-text long-field" name="requesturl" id="requesturl" value="'+app.mo_oauth_requesturl+'" placeholder="Enter request token endpoint"></div>');
        if(undefined != app.mo_oauth_input){
            jQuery("#discInput").val(app.mo_oauth_input);
            var inputs = app.mo_oauth_input.split(" ");
            for(i in inputs){
                var index = 'mo_oauth_'+inputs[i];
                var index_val = inputs[i];
                // console.log(app[index]);
            if(undefined != app[index])                
                jQuery(discovery).append('<div class="field-group"><label>'+index_val+'</label><input type="text" class="mo-normal-text long-field" name="'+index_val+'" id="'+index_val+'" value="'+app[index]+'" placeholder="Enter '+app.mo_oauth_appId+' '+index_val+'"><i class="fa mo-valid-icon"></i></div>');
            else
                jQuery(discovery).append('<div class="field-group"><label>'+index_val+'</label><input type="text" class="mo-normal-text long-field" name="'+index_val+'" id="'+index_val+'" value="" placeholder="Enter '+app.mo_oauth_appId+' '+index_val+'"><i class="fa mo-valid-icon"></i></div>');                
            }
        }
        if(undefined != app.mo_oauth_guide){ 
            jQuery(".mo-oauth-setup-guide").append('<a href="'+app.mo_oauth_guide+'" class="mo-oauth-setup-guide-link" target="_blank">&nbspSetup Guide</a>&nbsp');
        }               
        if(undefined != app.mo_oauth_video){
            jQuery(".mo-oauth-setup-guide").append('<a href="'+app.mo_oauth_video+'" class="mo-oauth-setup-video-link" target="_blank">&nbspVideo Guide</a>');
        }        
        if(undefined != app.mo_oauth_type){
            jQuery("#type").val(app.mo_oauth_type);
            if("oauth1" == app.mo_oauth_type)
                jQuery("#mo-oauth-scope").hide();
            else
                jQuery("#mo-oauth-scope").show();
        }
        if(undefined != app.mo_oauth_debug){
            if(true === app.mo_oauth_debug || 'true' == app.mo_oauth_debug)
                jQuery("#debug").prop('checked',true);
            else
                jQuery("#debug").prop('checked',false);
        }
        if(undefined != app.mo_oauth_send_header){
            if(true === app.mo_oauth_send_header || 'true' == app.mo_oauth_send_header)
                jQuery("#send_header").prop('checked',true);
            else
                jQuery("#send_header").prop('checked',false);
        }
        if(undefined != app.mo_oauth_send_body){
            if(true === app.mo_oauth_send_body || 'true' == app.mo_oauth_send_body)
                jQuery("#send_body").prop('checked',true);
            else
                jQuery("#send_body").prop('checked',false);
        }
        mooauth_get_summary();       
    }
    else{
         mooauth_get_step(1);
    }   
}
function mooauth_update_display_name_description(){
    var app_display_name = jQuery("#displayName").val();
    jQuery("#moauth_show_desc").html("This will displayed on SSO login button as<b> \"Login with " + app_display_name +"\"</b>");
}
/**
 * @param  {string} option { used to handle the ajax option similar to $_POST['option'] }
 * @param  {string} action { back (for back button click)| next (for next button click) | other actions }
 * @return {json object} data { setup wizard app data }
 */
function mooauth_get_data(option,action){
    var scopes = jQuery("#multi-select").dropdown('get value').split(",");
    console.log(option+" "+action);
    console.log(scopes);
    if("" != jQuery("#scope_list").val())
        var scope_list = JSON.parse(jQuery("#scope_list").val());
    else
        var scope_list = "";
    if('back' == action)
        var step = parseInt(jQuery("#step").val()) - 1;
    else if('next' == action)
        var step = parseInt(jQuery("#step").val()) + 1;
    else
        var step = parseInt(jQuery("#step").val());
    // console.log(step);
    var data={
        "action": "mo_outh_ajax",
        "mo_oauth_option": option,
        "mo_oauth_appId" : jQuery("#appId").val(),
        "mo_oauth_step"  : step,
        "mo_oauth_nonce" : jQuery("#nonce").val(),
        "mo_oauth_scopes": scopes,
        "mo_oauth_client_id" : jQuery("#clientId").val(),
        "mo_oauth_client_secret" : jQuery("#clientSecret").val(),
        "mo_oauth_app_name" : jQuery("#displayName").val(),
        "mo_oauth_type" : jQuery("#type").val(),
        "mo_oauth_scopes_list" : scope_list
    };
    if(jQuery("#authorize").length )
        data['mo_oauth_authorize'] = jQuery("#authorize").val();
    if(jQuery("#token").length )
        data['mo_oauth_token'] = jQuery("#token").val();
    if(jQuery("#userinfo").length )
        data['mo_oauth_userinfo'] = jQuery("#userinfo").val();    
    if(jQuery("#requesturl").length )
        data['mo_oauth_requesturl'] = jQuery("#requesturl").val();
    var input = jQuery("#discInput").val();
    if("" != input)
         data['mo_oauth_input'] = input;
     var inputs = input.split(" ");
     for(i in inputs){
        data['mo_oauth_'+inputs[i]] = jQuery("#"+inputs[i]).val();
        // console.log(inputs[i]);
    }
    if(jQuery(".mo-oauth-setup-guide").length){
        // console.log("guide availble");
        if(jQuery(".mo-oauth-setup-guide-link").length){
            // console.log("guide link availble");
            data['mo_oauth_guide'] = jQuery(".mo-oauth-setup-guide-link").attr("href");
        }
        if(jQuery(".mo-oauth-setup-video-link").length){
            // console.log("video link availble");
            data['mo_oauth_video'] = jQuery(".mo-oauth-setup-video-link").attr("href");
        }
    }
    if(jQuery("#debug").length){
        data['mo_oauth_debug'] = jQuery("#debug").is(":checked");
    }
    if(jQuery("#send_header").length){
        data['mo_oauth_send_header'] = jQuery("#send_header").is(":checked");
    }
    if(jQuery("#send_body").length){
        data['mo_oauth_send_body'] = jQuery("#send_body").is(":checked");
    }
    return data;
}
/**
 * handles stepper UI, buttons to be displayed -  next|finsih|test-finish|skip back|change application based on the current step number
 * @param  {int} step {setup wizard current step number}
 */
function mooauth_get_step(step){
    jQuery('#step').val(step);
    var step_num = parseInt(jQuery('#step').val());
    var selected_step = 'step'+ step_num;
    // console.log(selected_step);
    // console.log(step_num);
    for (i = 1; i <= last_step; i++) {
        var step = 'step'+i;
        if(i<step_num){
                jQuery('.icon-step'+i).removeClass('mo-multistep-root-active');                             
                jQuery('.icon-step'+i).removeClass('mo-multistep-root-incompleted'); 
                jQuery('.icon-step'+i).addClass('mo-multistep-root-completed');
                jQuery('.mo-label-step'+i).removeClass('mo-muisteplabel-active');                             
                jQuery('.mo-label-step'+i).removeClass('mo-muisteplabel-incompleted'); 
                jQuery('.mo-label-step'+i).addClass('mo-muisteplabel-completed');
                jQuery('.mo-muilti-step-connector'+i).addClass('mo-multistep-completed');
        }else{
                jQuery('.icon-step'+i).removeClass('mo-multistep-root-completed');                
                jQuery('.icon-step'+i).addClass('mo-multistep-root-incompleted'); 
                jQuery('.mo-label-step'+i).removeClass('mo-muisteplabel-completed');                
                jQuery('.mo-label-step'+i).addClass('mo-muisteplabel-incompleted');
                jQuery('.mo-muilti-step-connector'+i).removeClass('mo-multistep-completed');
                jQuery('.mo-muilti-step-connector'+i).removeClass('mo-multistep-active');     
        }
        if(step == selected_step){
            jQuery('#'+step).show();
            jQuery('.icon-step'+i).addClass('mo-multistep-root-active'); 
            jQuery('.mo-label-step'+i).addClass('mo-muisteplabel-active');
            jQuery('.mo-muilti-step-connector'+i).addClass('mo-multistep-active');
        }else{
            jQuery('#'+step).hide(); 
        }
    }
    jQuery('#step').val(step_num);
    if("1" == step_num){
        jQuery(".mo-button__footer").hide();
        jQuery(".mo-multistepper-root").hide();
        jQuery(".mo-skip__footer").show();
    }
    if("1" != step_num){     
        jQuery(".mo-button__footer").show();       
        jQuery(".mo-multistepper-root").show();     
        jQuery(".mo-skip__footer").hide();
    } 

    jQuery("#mo-btn-next").hide();
    jQuery("#mo-btn-finish").hide();
    jQuery("#mo-link-draft").hide(); 
    jQuery("#mo-btn-close").hide();
    jQuery("#mo-btn-test-finish").hide();
    jQuery("#mo-btn-test-re-run").hide();

    if(final_step == step_num){        
        mooauth_get_summary();
        jQuery("#mo-btn-finish").show();
    }

    if(last_step == step_num){
        mooauth_get_summary();
        jQuery("#mo-btn-test-finish").show();
    }

    if(final_step > step_num) {
        jQuery("#mo-btn-next").show();
        jQuery("#mo-link-draft").show();
        jQuery("#mo-btn-close").show();
    }
}
/**
 * initilizes summary screen fields
 */
function mooauth_get_summary(){
    jQuery(".mo-summary-name").empty();
    jQuery(".mo-summary-id").empty();
    jQuery(".mo-summary-secret").empty();
    jQuery(".mo-summary-scopes").empty();
    jQuery(".mo-summary-endpoints").empty();
    jQuery(".mo-summary-name").append("Login with "+jQuery("#displayName").val());
    jQuery(".mo-summary-id").val(jQuery("#clientId").val());
    jQuery(".mo-summary-secret").val(jQuery("#clientSecret").val());
    var scopes = jQuery("#multi-select").dropdown('get value').toString().replaceAll(","," ");
    jQuery(".mo-summary-scopes").append(scopes);
    if(jQuery("#authorize").length){
        jQuery(".mo-summary-endpoints").append('<li class="summary-form-row"><label>Authorization Endpoint :</label><div class="mo-summary-authorize mo-summary-data"></div><a class="mo-editstep" data-step="3"> </a></li>');
        jQuery(".mo-summary-authorize").text(jQuery("#authorize").val());
    }
    if(jQuery("#token").length){
        jQuery(".mo-summary-endpoints").append('<li class="summary-form-row"><label>Token Endpoint :</label><div class="mo-summary-token mo-summary-data"></div><a class="mo-editstep" data-step="3"> </a></li>');
        jQuery(".mo-summary-token").text(jQuery("#token").val());
    }
    if(jQuery("#userinfo").length){
        jQuery(".mo-summary-endpoints").append('<li class="summary-form-row"><label>Userinfo Endpoint :</label><div class="mo-summary-userinfo mo-summary-data"></div><a class="mo-editstep" data-step="3"> </a></li>');
        jQuery(".mo-summary-userinfo").text(jQuery("#userinfo").val());
    }
    if(jQuery("#requesturl").length){
        jQuery(".mo-summary-endpoints").append('<li class="summary-form-row"><label>Request Token Endpoint :</label><div class="mo-summary-requesturl mo-summary-data"></div><a class="mo-editstep" data-step="3"> </a></li>');
        jQuery(".mo-summary-requesturl").text(jQuery("#requesturl").val());
    }
    var input = jQuery("#discInput").val();
    if("" != input)
     var inputs = input.split(" ");
     for(i in inputs){        
        jQuery(".mo-summary-endpoints").append('<li class="summary-form-row"><label>'+inputs[i]+' :</label><div class="mo-summary-'+inputs[i]+' mo-summary-data"></div><a class="mo-editstep" data-step="3"> </a></li>');
        jQuery(".mo-summary-"+inputs[i]).text(jQuery("#"+inputs[i]).val());
        // console.log(inputs[i]);
    }
}

/**
 * calls when click on finish of summary scree to proceed with SSO test. It checks if any fields is missing and throws error
 */
function mooauth_input_validation(){
    var mo_auth_response = 'success';
     li =jQuery(".mo-summary-data");
     for (i = 0; i < li.length; i++) {
        if('input' === li[i].localName){
            var mo_auth_value = jQuery("#"+li[i].id).val();
        }else if('mo-summary-scopes mo-summary-data' !== li[i].className )
            var mo_auth_value = li[i].childNodes[0];
        if (undefined === mo_auth_value || '' === mo_auth_value ) {
                mo_auth_response = 'error';
            }   
    }
    if('error' == mo_auth_response){
        jQuery("#mo-btn-finish").tooltip({ items: "#mo-btn-finish", content: "ERROR: Some fields are missing. Please add correct input to proceed" , offset: [45, 170], delay: 4000});
        jQuery("#mo-btn-finish").tooltip("open");
        setTimeout(function() {jQuery(".ui-tooltip").fadeOut("slow"); jQuery("#mo-btn-finish").tooltip({ items: "#mo-btn-finish", content: ""});}, 5000);
    }
    return mo_auth_response
}

/**
 * calls on next|finish button click to manage the stepper
 */
function mooauth_steps_icr(){
    console.log("increment" );
    var step_num = parseInt(jQuery('#step').val()) + 1;
    var selected_step = 'step'+ step_num;
    // console.log(selected_step);
    // console.log(step_num);
    for (i = 1; i <= last_step; i++) {
        var step = 'step'+i;
        if(i<step_num){
                jQuery('.icon-step'+i).removeClass('mo-multistep-root-active');                            
                jQuery('.icon-step'+i).removeClass('mo-multistep-root-incompleted');  
                jQuery('.icon-step'+i).addClass('mo-multistep-root-completed');

                jQuery('.mo-label-step'+i).removeClass('mo-muisteplabel-active');                             
                jQuery('.mo-label-step'+i).removeClass('mo-muisteplabel-incompleted'); 
                jQuery('.mo-label-step'+i).addClass('mo-muisteplabel-completed'); 

                jQuery('.mo-muilti-step-connector'+i).addClass('mo-multistep-completed'); 
                jQuery('.mo-muilti-step-connector'+i).removeClass('mo-multistep-active');  
        }else{
                jQuery('.icon-step'+i).removeClass('mo-multistep-root-completed');                            
                jQuery('.icon-step'+i).addClass('mo-multistep-root-incompleted'); 

                jQuery('.mo-label-step'+i).removeClass('mo-muisteplabel-completed');                
                jQuery('.mo-label-step'+i).addClass('mo-muisteplabel-incompleted'); 

                jQuery('.mo-muilti-step-connector'+i).removeClass('mo-multistep-completed'); 
                jQuery('.mo-muilti-step-connector'+i).removeClass('mo-multistep-active');               
        }
        if(step == selected_step){
            jQuery('#'+step).show();
            jQuery('.icon-step'+i).addClass('mo-multistep-root-active');             
            jQuery('.mo-label-step'+i).addClass('mo-muisteplabel-active');
            jQuery('.mo-muilti-step-connector'+i).addClass('mo-multistep-active'); 
        }else{
            jQuery('#'+step).hide(); 
        }
    }
    jQuery('#step').val(step_num);
    jQuery(".mo-multistepper-root").show();
    jQuery(".mo-button__footer").show();
    jQuery(".mo-skip__footer").hide();
    if(final_step == step_num){
        mooauth_get_summary();
        jQuery("#mo-btn-next").hide();
        jQuery("#mo-link-draft").hide();
        jQuery("#mo-btn-close").hide();
        jQuery("#mo-btn-finish").show();
    }else{
        jQuery("#mo-btn-next").show();
        jQuery("#mo-link-draft").show();
        jQuery("#mo-btn-close").show();
        jQuery("#mo-btn-finish").hide();
    }
    if(last_step == step_num){
        jQuery("#mo-btn-next").hide();
        jQuery("#mo-link-draft").hide();
        jQuery("#mo-btn-close").hide();
        jQuery("#mo-btn-test-finish").show();
        jQuery("#mo-btn-test-re-run").hide();
    }
    jQuery("#mo-btn-back").val("Back");
    if(2 == step_num){
        jQuery("#mo-btn-back").val("Change Application");
    }
}
/**
 * calls on back button click to manage stepper
 */
function mooauth_steps_dcr(){
    var step_num = parseInt(jQuery('#step').val()) -1;
    var selected_step = 'step'+ step_num;
    // console.log(selected_step);
    // console.log(step_num);
    for (i = 1; i <= last_step; i++) {
        if(i<step_num){                
                jQuery('.icon-step'+i).addClass('mo-multistep-root-completed');                                  
                jQuery('.icon-step'+i).removeClass('mo-multistep-root-incompleted'); 

                jQuery('.mo-label-step'+i).removeClass('mo-muisteplabel-incompleted'); 
                jQuery('.mo-label-step'+i).addClass('mo-muisteplabel-completed');

                jQuery('.mo-muilti-step-connector'+i).addClass('mo-multistep-completed');  
        }else{
                jQuery('.icon-step'+i).removeClass('mo-multistep-root-completed');                                
                jQuery('.icon-step'+i).addClass('mo-multistep-root-incompleted');

                jQuery('.mo-label-step'+i).removeClass('mo-muisteplabel-completed');                
                jQuery('.mo-label-step'+i).addClass('mo-muisteplabel-incompleted'); 
                
                jQuery('.mo-muilti-step-connector'+i).removeClass('mo-multistep-active'); 
                jQuery('.mo-muilti-step-connector'+i).removeClass('mo-multistep-completed'); 
        }
        var step = 'step'+i;
        if(step == selected_step){
            console.log("show" +step);
            jQuery('#'+step).show();
            jQuery('.icon-step'+i).addClass('mo-multistep-root-active');
            jQuery('.mo-label-step'+i).addClass('mo-muisteplabel-active');
            jQuery('.mo-muilti-step-connector'+i).addClass('mo-multistep-active'); 
        }else{
            console.log("hide" +step);
            jQuery('.mo-muilti-step-connector'+i).removeClass('mo-multistep-active'); 
            jQuery('.mo-label-step'+i).removeClass('mo-muisteplabel-active');

            jQuery('.icon-step'+i).removeClass('mo-multistep-root-active'); 
            jQuery('#'+step).hide(); 
        }
        jQuery("#mo-btn-back").val("Back");
        if(2 == step_num){
            jQuery("#mo-btn-back").val("Select New Application");
        }
    }
    jQuery('#step').val(step_num);
    if(1 == step_num){        
        jQuery(".mo-multistepper-root").hide();
        jQuery(".mo-button__footer").hide();
        jQuery(".mo-skip__footer").show();
    }
    if(5 == step_num){
        jQuery("#mo-btn-finish").show();                
    }
    else{
        jQuery("#mo-btn-finish").hide(); 
        jQuery("#mo-btn-next").show();
        jQuery("#mo-link-draft").show();
        jQuery("#mo-btn-close").show();
    }
    jQuery("#mo-btn-test-finish").hide();  
    jQuery("#mo-btn-test-re-run").hide();              
}
function mooauth_copyUrl() {
    var copyText = document.getElementById("callbackurl");
    copyText.select();
    copyText.setSelectionRange(0, 99999); 
    document.execCommand("copy");
}

/**
 * hide|display client secret 
 */
function mooauth_showClientSecret(clientSecretId,show_buttonId){
    var field = document.getElementById(clientSecretId);
    var show_button = document.getElementById(show_buttonId);
    if(field.type == "password"){
        field.type = "text";
        show_button.className = "fa fa-eye-slash";
    }
    else{
        field.type = "password";
        show_button.className = "fa fa-eye";
    }
}
/**
 * SSO test is invoked
 */
function mooauth_testConfiguration(site_url){
    var mo_oauth_app_name = jQuery("#displayName").val();
    var myWindow = window.open( site_url + '/?option=testattrmappingconfig&app='+mo_oauth_app_name, "Test Attribute Configuration", "width=600, height=600");
}