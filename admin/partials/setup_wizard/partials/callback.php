<?php
/**
 * setup wizard step 2 - show callback URL
 */
function mooauth_client_setup_callback(){
	echo '	<!-- content main --> 
	        <h4>Setting up a Relying Party<span class="mo-oauth-setup-guide"></span></h4>
	        <p>
    	        <span class="mo-oauth-highlight-guide-notice" >Keep the setup guide handy or open it in a new window before proceeding with the setup</span><br>

	        	Copy below callback URL (111Redirect URI) and configure it in your OAuth Provider
	        </p>
	        <div class="field-group">
	            <label>Callback URL</label> 
	            <input title="Copy this Redirect URI and provide to your provider"
				 type="text" class="mo-normal-text" id="callbackurl" name="url" value="'.esc_url_raw(site_url()).'"> 
	           <div class="tooltip" style="display: inline;"><span class="tooltiptext" id="moTooltip">Copy to clipboard</span><i class="fa fa-clipboard fa-border" style="font-size:20px; align-items: center;vertical-align: middle;" aria-hidden="true" onclick="mooauth_copyUrl()" onmouseout="mooauth_outFunc()"></i></div>
	            <div class="description">
	                <p>
						"Callback URL/Redirect URL" needs to be configured in your provider.
	                </p>                
	            </div>
	        </div>';?>
	        <script type="text/javascript">
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

			}
		</script>
<?php
}

?>