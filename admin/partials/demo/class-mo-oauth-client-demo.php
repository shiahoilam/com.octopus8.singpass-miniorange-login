<?php
	
	class MOOAuth_Client_Admin_RFD {
	
		public static function requestfordemo() {
			self::demo_request();
		}

		public static function demo_request(){
			$democss = "width: 350px; height:35px;";
		?>
		<div class="mo_demo_layout">
			<h3> <?php esc_html_e('Request for Demo/ Trial','miniorange-login-with-eve-online-google-facebook'); ?>  </h3>
			<hr>
			<?php esc_html_e('Want to try out the paid features before purchasing the license? Just let us know which plan you\'re interested in and we will setup a demo for you.','miniorange-login-with-eve-online-google-facebook');?>
			<form method="post" action="">
				<table class="mo_oauth_cloud_demo_outer_table">
				<tr>
						<td>
							<!-- trial/demo -->
							<input type="hidden" name="option" value="mo_oauth_client_demo_request_form" />
							<?php wp_nonce_field('mo_oauth_client_demo_request_form', 'mo_oauth_client_demo_request_field'); ?>
							<table class="mo_oauth_demo_table_layout">
								<!-- First form start -->

								<tr>
									<td><strong>Email id <p style="display:inline;color:red;">*</p>: </strong></td>
								</tr>
								<tr>
									<td><input required type="email" style="<?php echo esc_attr($democss); ?>" name="mo_auto_create_demosite_email" placeholder="We will use this email to setup the demo for you" value="<?php echo esc_attr(get_option("mo_oauth_admin_email")); ?>" /></td>
								</tr>
								<tr>
									<td style="padding-top:20px"><strong><?php esc_html_e('Request a demo for','miniorange-login-with-eve-online-google-facebook'); ?> <p style="display:inline;color:red;">*</p>: </strong></td>
								</tr>
								<tr>
									<td>
									<select required style="<?php echo esc_attr($democss); ?>" name="mo_auto_create_demosite_demo_plan" id="mo_oauth_client_demo_plan_id">
										<option disabled value="" selected>------------------ Select ------------------</option>
										<option value="miniorange-oauth-client-standard-common@11.6.1">WP <?php echo esc_html(MO_OAUTH_PLUGIN_NAME); ?> Standard Plugin</option>
										<option value="mo-oauth-client-premium@21.5.3">WP <?php echo esc_html(MO_OAUTH_PLUGIN_NAME); ?> Premium Plugin</option>
										<option value="miniorange-oauth-client-enterprise@31.5.7">WP <?php echo esc_html(MO_OAUTH_PLUGIN_NAME); ?> Enterprise Plugin</option>
										<option value="miniorange-oauth-client-allinclusive@48.3.0">WP <?php echo esc_html(MO_OAUTH_PLUGIN_NAME); ?> All Inclusive Plugin</option>
										<option value="Not Sure">Not Sure</option>
									</select>
									</td>
								</tr>	
								<tr>
									<td style="padding-top:20px"><strong><?php esc_html_e('Usecase','miniorange-login-with-eve-online-google-facebook'); ?><p style="display:inline;color:red;">*</p> : </strong></td>
								</tr>
								<tr>
									<td>
									<textarea type="text" minlength="15" name="mo_auto_create_demosite_usecase" class="mo_oauth_demo_request_usecase" rows="4" placeholder="<?php esc_html_e('Example. Login into wordpress using Cognito, SSO into wordpress with my company credentials, Restrict gmail.com accounts to my wordpress site etc.','miniorange-login-with-eve-online-google-facebook'); ?>" required value=""></textarea>
									</td>
								</tr>
							</table>	
						</td>
							
						<td class="mo_oauth_demo_request_veretical_line">
							<!-- vertical line here -->
						</td>

						<td>
							<!-- demo checkbox here -->
							<p><strong><?php esc_html_e('Select the Add-ons you are interested in (Optional)','miniorange-login-with-eve-online-google-facebook');?> :</strong></p>
					        <p><i><strong>(<?php esc_html_e('Note','miniorange-login-with-eve-online-google-facebook');?>: </strong> <?php esc_html_e('All-Inclusive plan entitles all the addons in the license cost itself.','miniorange-login-with-eve-online-google-facebook');?> )</i></p>
						  		<table>
								<?php
						  		$count=0;
						        foreach(MOOAuth_Client_Admin_Addons::$all_addons as $key => $value)
								{
									if($key!=0 && $value!=0 && true === $value['in_allinclusive'])
									{	
										if($count==0)
										{
											?>
											<tr>
												<td>
													<input type="checkbox"  class="mo_oauth_demo_form_checkbox" style="margin:7px 5px 7px 5px" name="<?php echo esc_attr($value['tag']); ?>" value="true"> <?php echo esc_html($value['title']); ?><br/>
												</td>
											
											<?php
											$count=$count+1;
										}
									
										else if($count==1)
										{
											?>
											
												<td>
													<input type="checkbox"  class="mo_oauth_demo_form_checkbox" style="margin:7px 5px 7px 5px" name="<?php echo esc_attr($value['tag']); ?>" value="true"> <?php echo esc_html($value['title']); ?><br/>
													
												</td>
											</tr>		

											<?php
											$count=0;
										}
									
									}
						        }
						        ?>
								</table>
						</td>
					</tr>
				</table>
				<input type="submit" class="mo_oauth_demo_submit_button" name="submit" value="<?php esc_html_e('Submit Demo Request','miniorange-login-with-eve-online-google-facebook'); ?>" class="button button-primary button-large" />
			</form>
		</div>			
	
			<!-- VIDEO DEMO DOWN -->

				<div class="mo_oauth_video_demo_container mo_demo_layout">
					<h3><?php esc_html_e('Request for Video Demo','miniorange-login-with-eve-online-google-facebook'); ?>  </h3>
					<hr>
					<div style="display:flex">
						<div class="mo_oauth_video_demo_container_form">
							<form method="post" action="">
								<input type="hidden" name="option" value="mo_oauth_client_video_demo_request_form" />
								<?php wp_nonce_field('mo_oauth_client_video_demo_request_form', 'mo_oauth_client_video_demo_request_field'); ?>
								<table class="mo_demo_table_layout">
								<tr><td>
										<div><strong>Email id <p style="display:inline;color:red;">*</p>: </strong></div>
										<div><input type="text" class="mo_oauth_video_demo_email" style="<?php echo esc_attr($democss); ?>" placeholder="We will use this email to setup the demo for you" name="mo_oauth_video_demo_email" ></div>
							</tr></td>
								<tr>
									<td><div><strong>Date<p style="display:inline;color:red;">*</p>: </strong></div>
									<div><input type="date" class="mo_oauth_video_demo_date" style="<?php echo esc_attr($democss); ?>" name="mo_oauth_video_demo_request_date" placeholder="Enter the date for demo"></div>
								</td>	
								</tr>
								
								<tr>
									<td>
									<div><strong>Local Time<p style="display:inline;color:red;">*</p>: </strong></div>
									<div><input type="time" class="mo_oauth_video_demo_time" placeholder="Enter your time" style="<?php echo esc_attr($democss); ?>" name="mo_oauth_video_demo_request_time">
										<input type="hidden" name="mo_oauth_video_demo_time_diff" id="mo_oauth_video_demo_time_diff"></div>
									</td>
								</tr>
								<tr>
									<td style="color:grey;">Eg:- 12:56, 18:30, etc.</td>
								</tr>
									<tr><td><div>
										<strong>Usecase/ Any comments:<p style="display:inline;color:red;">*</p>: </strong></div>
										<div><textarea name="mo_oauth_video_demo_request_usecase_text" class="mo_oauth_video_demo_form_usecase" style="resize: vertical; width:350px; height:150px;" minlength="15" placeholder="Example. Login into wordpress using Cognito, SSO into wordpress with my company credentials, Restrict gmail.com accounts to my wordpress site etc."></textarea>
									</div></td></tr>
									</table>
								</div>
						
						<div class="mo_oauth_demo_container_gif_section mo_demo_table_layout">
							<div class="mo_oauth_video_demo_message">
								Your overview <a style="color:#012970"><strong>Video Demo</strong></a> will include
							</div>
							<div class="mo_oauth_video_demo_bottom_message">
								<img class="mo_oauth_video_demo_gif" src="<?php echo esc_attr(plugin_dir_url( __FILE__ )) .'/img/setup-gif.jpg'; ?>" alt="mo-demo-png">
							</div>
							<div class="mo_oauth_video_demo_bottom_message" >
									<strong>You can set up a screen share meeting with our developers to walk you through our plugin featuers.</strong>
								<div class="mo_oauth_video_demo_bottom_message">
									<img class="mo_oauth_video_demo_icon" src="<?php echo esc_attr(plugin_dir_url( __FILE__ )) .'/img/check.png'; ?>"  alt="">
									Overview of all Premium Plugin features.
								</div>	
								<div style="margin-top:10px">
									<img class="mo_oauth_video_demo_icon" src="<?php echo esc_attr(plugin_dir_url( __FILE__ )) .'/img/support.png'; ?>"  alt="">
									Get a guided demo from a Developer via screen share meeting.
								</div>
							</div>
						</div>
					</div>
					<table >
                        <tr>
                            <td>
							<input type="submit" class="mo_oauth_demo_submit_button" name="submit" value="<?php esc_html_e('Submit Demo Request','miniorange-login-with-eve-online-google-facebook'); ?>" class="button button-primary button-large" />
                            </td>
                        </tr>
			    	</table>	
					</form>					
				</div>	
			
			<script>
				var d = new Date();
    			var n = d.getTimezoneOffset();
    			document.getElementById("mo_oauth_video_demo_time_diff").value = n;
			</script>	
		<?php
		}
	}
