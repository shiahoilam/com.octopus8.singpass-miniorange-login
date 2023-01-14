
jQuery(document).ready(function($) {

    jQuery(function() {
        if($('#mo_oauth_debug_check').is(":checked")){
            jQuery("#mo_oauth_enable").show();

            jQuery("#mo_oauth_debug_check").click(function() {
                mo_oauth_ajax_toggle_function();
            });
                
            }
            
        else{
            jQuery("#mo_oauth_enable").hide();
            jQuery("#mo_oauth_debug_check").click(function() {
                mo_oauth_ajax_toggle_function();
            });
        }

                function mo_oauth_ajax_toggle_function(){
                    if (jQuery("#mo_oauth_debug_check").is(":checked")) {

                        var data = {
                            "action": "mo_oauth_debug_ajax",
                            "mo_oauth_option": "mo_oauth_reset_debug",
                            "mo_oauth_mo_oauth_debug_check": "on",
                            "mo_oauth_nonce" : jQuery('input[name="mo_oauth_reset_debug"]').val()
                        }
                        jQuery.post( 'admin-ajax.php' , data, function(response){                            
                            jQuery("#mo_oauth_enable").show();
        
                        });
                    
                    }else {
                        var data = {
                            "action": "mo_oauth_debug_ajax",
                            "mo_oauth_option": "mo_oauth_reset_debug",
                            "mo_oauth_mo_oauth_debug_check": "off",
                            "mo_oauth_nonce" : jQuery('input[name="mo_oauth_reset_debug"]').val()
                        }
                        jQuery.post( 'admin-ajax.php' , data, function(response){
                                jQuery("#mo_oauth_enable").hide();
                            
                        });
                    }
                };
    }); 
})  


function mo_oauth_valid_query(f) {
    !(/^[a-zA-Z?,.\(\)\/@ 0-9]*$/).test(f.value) ? f.value = f.value.replace(
        /[^a-zA-Z?,.\(\)\/@ 0-9]/, '') : null;
}


jQuery(document).ready(function($) {

    jQuery("#contact_us_phone").intlTelInput({
        nationalMode: false,
    });

    jQuery(function() {
        jQuery("#mo_oauth_setup_call_div").hide();

        jQuery("#oauth_setup_call").click(function() {
            if (jQuery(this).is(":checked")) {
                jQuery("#mo_oauth_setup_call_div").show();
                document.getElementById("issue_dropdown").required = true;
                document.getElementById("calldate").required = true;
                document.getElementById("mo_oauth_setup_call_time").required = true;

            } else {
                jQuery("#mo_oauth_setup_call_div").hide();
                document.getElementById("issue_dropdown").required = false;
                document.getElementById("calldate").required = false;
                document.getElementById("mo_oauth_setup_call_time").required = false;
            }
        });
    });

    jQuery('#calldate').datepicker({
        dateFormat: 'd MM, yy',
        beforeShowDay: $.datepicker.noWeekends,
        minDate: 1,
    });
    jQuery('#issue_dropdown').change(function() {
        if (document.getElementById("sso_setup_issue").selected) {
            document.getElementById("setup_guide_link").style.display = "table-row";
        } else {
            document.getElementById("setup_guide_link").style.display = "none";
        }
        if (document.getElementById("other_issue").selected) {
            document.getElementById("required_mark").style.display = "table-row";
            document.getElementById("issue_description").required = true;
        } else {
            document.getElementById("required_mark").style.display = "none";
            document.getElementById("issue_description").required = false;
        }
    });
    var d = new Date();
    var n = d.getTimezoneOffset();
    document.getElementById("mo_oauth_time_diff").value = n;
});
