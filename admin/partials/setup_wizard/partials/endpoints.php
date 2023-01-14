<?php
/**
 * setup wizard step 3 - set app name, endpoints/discovery
 */
function mooauth_client_setup_endpoints(){
	echo '	<!-- content main --> 
	        <h4>Provider Metadata<span class="mo-oauth-setup-guide"></span></h4>';
	echo '	        <div class="field-group">
			    <label>App name</label>
			    <input title="Display Name"
			    type="text" class="mo-normal-text" name="displayName" id="displayName" value="" placeholder="Company Name" onkeyup="mooauth_update_display_name_description()" >
			    <div class="description">
			      <p id="moauth_show_desc"> </p>
			    </div>
			  </div>';

	echo	'<div class="mo-discovery">
	       	</div>';
}

?>