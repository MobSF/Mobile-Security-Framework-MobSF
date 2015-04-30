define('10003592_js/finappConfig',[],function(){ return ({
	dependsJs : ['/js/ui/loginFormBuilder.js', '/js/ext/crypto/pidcrypt.js', '/js/ext/crypto/pidcrypt_util.js', '/js/ext/crypto/asn1.js', '/js/ext/crypto/jsbn.js', '/js/ext/crypto/rng.js', '/js/ext/crypto/prng4.js', '/js/ext/crypto/rsa.js', '/js/ext/crypto/PKI_Library.js']
}) });
define('10003592_js/common/dataParser',[], function() {

    

	var DataParser = function() {

		var SITE_LOGIN_FORM_API = 'siteLoginForm';

		var ADD_SITE_ACCOUNT_API = 'addSiteAccount';

		var ACCOUNTS_FOR_SITE_API = "siteAccountByMemSiteAccId";

		var SITE_ACCOUNT_CREDENTIALS_API = "siteAccountCredentails"

		var SITE_ACCOUNT_CREDENTAILS_FORMS_API = "siteAccountCredentailForms";

		var MEM_PREF_VALUE = "getMemPrefValue";

		var SITE_ACCOUNT_MFA_Q_AND_A = "siteAccountMfaQuestionsAndAnswers";

		var UPDATE_SITE_ACCOUNT_CREDENTAILS_API = "updateSiteAccountCredentials";



		var _parseSiteAccount = function( response ) {

			var result = {};
			if( typeof response != 'undefined' && response[0] ) {
				response = response[0];
				var siteInfo = {};
				var _siteInfo = response.siteInfo;
				siteInfo.siteId = _siteInfo.siteId;
				siteInfo.displayName = _siteInfo.defaultDisplayName;
				siteInfo.baseUrl = _siteInfo.baseUrl;
				siteInfo.siteLevelHelpText = _siteInfo.defaultHelpText;
				siteInfo.isAlreadyAddedByUser = _siteInfo.isAlreadyAddedByUser;
				//siteInfo.mfaType = _siteInfo.mfaType;
				if( _siteInfo.contentServiceInfos ) {
					$.each(_siteInfo.contentServiceInfos, function(key, val) {
	            		if( !siteInfo.loginUrl && val.loginUrl ) {
	            			siteInfo.loginUrl = val.loginUrl;
	            		}
	            		if( !siteInfo.containers ) {
	            			siteInfo.containers = val.containerInfo.containerName;
	            		} else {
	            			siteInfo.containers += ', '+ val.containerInfo.containerName;
	            		}
	        		});
	        	} else if( _siteInfo.enabledContainers ) {
					$.each(_siteInfo.enabledContainers, function(key, val) {
	            		if( !siteInfo.containers ) {
	            			siteInfo.containers = val.containerName;
	            		} else {
	            			siteInfo.containers += ', '+ val.containerName;
	            		}
	        		});
	        	}
        	//TODO : Currently commenting out since api is not returnin the value
        	//siteInfo.mfaTypeId = _siteInfo.mfaType.typeId;
	        	result.siteInfo = siteInfo;
	        	result.siteAccountId = response.siteAccountId;
				return result;
			}
			return result;
		};

		var _parseSiteLoginForm = function( response ) {
			var result = {};
			result.components = response.componentList;
			result.loginLevelHelpText = response.defaultHelpText;
			return result;
		}

		var _parseSiteAccountCredentailForms = function( forms ) {
			var formWithUser = [];
			if( forms && forms.length > 0 ) {
				$.each(forms, function(index, account) {
					if( account && account.form && account.form.componentList ) {
						var components = account.form.componentList;
						var siteAccountId = account.siteAccountId;
						if( components ) {
							$.each(components, function(index, component) {
								if( component.fieldType.typeName == 'IF_LOGIN' ) {
									var result = { siteAccountId : siteAccountId, userId : component.value };
									formWithUser.push(result);
									return;
								}
							});
						}
					}
				});
			}
			return formWithUser;
		}

		var _getSiteAccountInputData = function(siteAccountId) {
			var result = {};
			result.method = 'POST';
			result.data = {'siteAccountFilter.memSiteAccIds[0]' : ''+siteAccountId+''};
			result.apiUrl = ACCOUNTS_FOR_SITE_API;
			return result;	
		};		

		var _getSiteLoginForm = function(siteId, siteAccountId)	{
			var result = {};
			result.method = 'POST';
			if(siteAccountId != undefined && !isNaN(siteAccountId) ){
				result.data = { 'memSiteAccId' : siteAccountId };
				result.apiUrl = SITE_ACCOUNT_CREDENTIALS_API;
			} else { 
				result.data = { 'siteId' : siteId };
				result.apiUrl = SITE_LOGIN_FORM_API;
			}
			return result;			
		}

		var _getSiteAccountCredenailFormsInputData = function(siteId)	{
			var result = {};
			result.method = 'POST';
			result.data = {'siteId':siteId };
			result.apiUrl = SITE_ACCOUNT_CREDENTAILS_FORMS_API;
			return result;			
		}

		var _getMemPrefInputData = function( key ) {
			var result = {};
			result.data = { 'preferenceKey' : 'externalAccTncRevision' };
			result.method = 'POST';
			result.apiUrl = MEM_PREF_VALUE;
			return result;
		}

		var _getMfaQAInputData = function( siteAccountId ) {
			var result = {};
			result.method = 'POST';
			result.data = {'memSiteAccId': ''+siteAccountId+'' };
			result.apiUrl = SITE_ACCOUNT_MFA_Q_AND_A;
			return result;
		}

		var _getGraphInputData = function(siteId, siteAccountId, tncEnabled, mfaEnabled, alreadyAdded) {
			var graphInput = {};
			var index = 0;

			graphInput[index++]  = _getSiteLoginForm(siteId, siteAccountId);

			/*
			** To get public key for encryption
			** make a call to api only when key is previously not available
			*/

			if(Utilities.getParam('encrypt_data')){
				if(!PKI.isKeyAvailable()) {
					graphInput[index++] = _getDataEncryptionServiceData(); 
				}
			}

			if(alreadyAdded && Utilities.getParam('added_sites_with_credentails')){ 
				graphInput[index++] = _getSiteAccountCredenailFormsInputData(siteId); 
			}

			if( siteAccountId && !isNaN(siteAccountId) && mfaEnabled) {
				graphInput[index++] = _getMfaQAInputData(siteAccountId);
			}
			if( tncEnabled ) {
				graphInput[index++] = _getMemPrefInputData();
			}
			return graphInput;
		}

		var _getSiteLoginFormPostData = function( loginFormJsonData, formFieldMap, siteId, siteAccountId, mfaQnAJsonData ) {
			var result = {};
        	result.data = {};
        	if( siteAccountId && !isNaN(siteAccountId) ) {
        		result.apiUrl = UPDATE_SITE_ACCOUNT_CREDENTAILS_API;
				result.data['memSiteAccId'] = siteAccountId;
				if( mfaQnAJsonData && mfaQnAJsonData.length > 0 ) {
					_convertMfaFormDataToServerJson( mfaQnAJsonData, 'mfaQuestionAnswers', formFieldMap, result.data);
					result.data['mfaQuestionAnswers.enclosedType'] = 'com.yodlee.core.accountmanagement.MfaQuestionAnswer';
				}
        	} else {
        		result.apiUrl = ADD_SITE_ACCOUNT_API;
				result.data['siteId'] = siteId;
			}

      		LoginFormBuilder.convertLoginFormDataToServerJson( loginFormJsonData, 'credentialFields', formFieldMap, result.data);
        	result.method = 'POST';
        	return result;
		}

		var _convertMfaFormDataToServerJson = function(obj, prefix, inputVals, map) {
			if( !map ) { map = {} };
			if( Object.prototype.toString.call(obj) === '[object Array]' ) {
				var j;
				for(j=0;j<obj.length;j++) {
					_convertMfaFormDataToServerJson(obj[j], prefix+'['+j+']', inputVals, map);
				}
			} else if( typeof obj == 'object' ) {
				var inputValue = $.trim(inputVals['mfaAnswer_'+obj.mfaQuestionAnswerId]);
				if( inputValue != '*****' ) {
					var key;
					for(key in obj) {
						if( key == 'mfaAnswer' ) {
							_convertMfaFormDataToServerJson(inputValue, prefix+'.'+key, inputVals, map);
						} else {
							_convertMfaFormDataToServerJson(obj[key], prefix+'.'+key, inputVals, map);
						}
					}
				}				
			} else {
				map[prefix] = ''+obj+'';
			}
		}

		var _getSiteAccountsInputData = function(siteAccountId) {
			var result = {};
			result.method = 'POST';
			result.data = {'siteAccountFilter.memSiteAccIds[0]' : '' + siteAccountId + '', 'notrim' : 'true' };
			result.apiUrl = ACCOUNTS_FOR_SITE_API;
			return result;	
		};	

        var isPopularSitesEnabled = function() {
            var value = Utilities.getParam('added_sites_with_credentails');
            if( value == 'true' || value === true ) {
                return true;
            }
            return false;
        }



        var _getDataEncryptionServiceData = function() {

			var result = {};

			result.method = 'POST';

			result.data = {};

			result.apiUrl = 'getPublicKey';

			return result;	

		};	



		return {
			parseSiteAccount : _parseSiteAccount,
	        parseSiteLoginForm : _parseSiteLoginForm,
	        parseSiteAccountCredentailForms : _parseSiteAccountCredentailForms,
	        getSiteLoginFormPostData : _getSiteLoginFormPostData,
	        getGraphInputData : _getGraphInputData,
	        getSiteAccountsInputData : _getSiteAccountsInputData,
	        getDataEncryptionServiceData : _getDataEncryptionServiceData
	    }
	}

	return new DataParser();
});


define('10003592_js/models/siteAccount',['10003592_js/common/dataParser'], function(DataParser) {
	var SiteAccount = Backbone.Model.extend({

		parse : function(response) {
			return DataParser.parseSiteAccount(response);
		}
	});
  return SiteAccount;
});
;
define("handlebars", (function (global) {
    return function () {
        var ret, fn;
       fn = function () {
            						this.Handlebars = Handlebars;
            						return this.Handlebars;
          						};
        ret = fn.apply(global, arguments);
        return ret || global.Handlebars;
    };
}(this)));

define('10003592_js/compiled/finappCompiled',['handlebars'], function(Handlebars) {
  var template = Handlebars.template, templates = Handlebars.templates = Handlebars.templates || {};
templates['baseLayout'] = template(function (Handlebars,depth0,helpers,partials,data) {
  helpers = helpers || Handlebars.helpers;
  var buffer = "", stack1, stack2, foundHelper, tmp1, self=this, functionType="function", helperMissing=helpers.helperMissing, undef=void 0, escapeExpression=this.escapeExpression;

function program1(depth0,data) {
  
  var buffer = "", stack1, stack2, stack3;
  buffer += "\n		";
  stack1 = 3;
  stack2 = 2;
  foundHelper = helpers.breadcrumb;
  stack3 = foundHelper || depth0.breadcrumb;
  if(typeof stack3 === functionType) { stack1 = stack3.call(depth0, stack2, stack1, { hash: {} }); }
  else if(stack3=== undef) { stack1 = helperMissing.call(depth0, "breadcrumb", stack2, stack1, { hash: {} }); }
  else { stack1 = stack3; }
  buffer += escapeExpression(stack1) + "\n	";
  return buffer;}

  buffer += "﻿<div>\n	";
  foundHelper = helpers.showBreadCrumb;
  stack1 = foundHelper || depth0.showBreadCrumb;
  stack2 = helpers['if'];
  tmp1 = self.program(1, program1, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n	<div id=\"header\"></div>\n	<div id=\"content\"></div>\n	<div id=\"status\"></div>\n</div>";
  return buffer;});
templates['error'] = template(function (Handlebars,depth0,helpers,partials,data) {
  helpers = helpers || Handlebars.helpers;
  var buffer = "", stack1, foundHelper, self=this, functionType="function", helperMissing=helpers.helperMissing, undef=void 0, escapeExpression=this.escapeExpression;


  buffer += "<div class=\"row errorSection\">\n	<div class=\"small-12 medium-12 large-12 error-description\">\n		";
  foundHelper = helpers.errorDescription;
  stack1 = foundHelper || depth0.errorDescription;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "errorDescription", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\n	</div>\n</div>";
  return buffer;});
templates['header'] = template(function (Handlebars,depth0,helpers,partials,data) {
  helpers = helpers || Handlebars.helpers;
  var buffer = "", stack1, stack2, stack3, stack4, foundHelper, tmp1, self=this, functionType="function", helperMissing=helpers.helperMissing, undef=void 0, escapeExpression=this.escapeExpression, blockHelperMissing=helpers.blockHelperMissing;

function program1(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n			<div id=\"siteLogoDiv\" style=\"display:none\">\n				<img src=\"";
  stack1 = "site_logo_url";
  foundHelper = helpers.param;
  stack2 = foundHelper || depth0.param;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "param", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "&siteId=";
  foundHelper = helpers.siteId;
  stack1 = foundHelper || depth0.siteId;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "siteId", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\"/> \n			</div>\n		";
  return buffer;}

function program3(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n				<div class=\"baseUrl\">\n					<i class=\"yodlee-font-icon svg_home web\" aria-hidden=\"true\"></i><a href=\"";
  foundHelper = helpers.baseUrl;
  stack1 = foundHelper || depth0.baseUrl;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "baseUrl", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" class=\"popwin\">";
  foundHelper = helpers.baseUrl;
  stack1 = foundHelper || depth0.baseUrl;
  foundHelper = helpers.domain;
  stack2 = foundHelper || depth0.domain;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "domain", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</a>\n				</div>\n			";
  return buffer;}

function program5(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n				<div class=\"loginUrl\">\n					<i class=\"yodlee-font-icon svg_secure lock\" aria-hidden=\"true\"></i><a href=\"";
  foundHelper = helpers.loginUrl;
  stack1 = foundHelper || depth0.loginUrl;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "loginUrl", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" class=\"popwin\">";
  foundHelper = helpers.loginUrl;
  stack1 = foundHelper || depth0.loginUrl;
  foundHelper = helpers.domain;
  stack2 = foundHelper || depth0.domain;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "domain", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</a>\n				</div>\n			";
  return buffer;}

  buffer += "<div class=\"row collapse\">\n	<div class=\"small-11 medium-portrait-3 medium-3 medium-portrait-offset-1 medium-offset-1 medium-min-11 medium-min-offset-0 column siteLogo\">\n		";
  stack1 = "true";
  stack2 = "==";
  stack3 = "show_account_logo";
  foundHelper = helpers.ifCond;
  stack4 = foundHelper || depth0.ifCond;
  tmp1 = self.program(1, program1, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  if(foundHelper && typeof stack4 === functionType) { stack1 = stack4.call(depth0, stack3, stack2, stack1, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack4, stack3, stack2, stack1, tmp1); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n		<div id=\"siteLogoDisplayName\" role=\"heading\" aria-level=\"2\" class=\"siteDisplayName\">";
  foundHelper = helpers.displayName;
  stack1 = foundHelper || depth0.displayName;
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</div>				\n	</div>\n	<div class=\"small-1  medium-min-1 column show-for-small-only show-for-medium-min hide-for-medium-portrait\">\n		<i class=\"yodlee-font-icon svg_info info y-tooltip right\" tooltip-width=\"250\" tooltip-title=\"";
  stack1 = "site_login_more_help_text";
  stack2 = {};
  foundHelper = helpers.loginUrl;
  stack3 = foundHelper || depth0.loginUrl;
  stack2['_SITE_LOGIN_URL_'] = stack3;
  foundHelper = helpers.containers;
  stack3 = foundHelper || depth0.containers;
  stack2['_CONTAINERS_'] = stack3;
  foundHelper = helpers.__;
  stack3 = foundHelper || depth0.__;
  tmp1 = {};
  tmp1.hash = stack2;
  if(typeof stack3 === functionType) { stack1 = stack3.call(depth0, stack1, tmp1); }
  else if(stack3=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, tmp1); }
  else { stack1 = stack3; }
  buffer += escapeExpression(stack1) + "\" mouseleave=\"false\" tabindex=\"0\" role=\"button\" aria-label=\"site login information\"></i>\n	</div>	\n	<div class=\"small-10 medium-portrait-7 medium-7 medium-min-single-col medium-min-pull-1 column\">\n		<div class=\"siteUrl\">\n			";
  foundHelper = helpers.baseUrl;
  stack1 = foundHelper || depth0.baseUrl;
  stack2 = helpers['if'];
  tmp1 = self.program(3, program3, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n			";
  foundHelper = helpers.loginUrl;
  stack1 = foundHelper || depth0.loginUrl;
  stack2 = helpers['if'];
  tmp1 = self.program(5, program5, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n		</div>\n	</div>\n	<div class=\"medium-portrait-1 medium-1 column hide-for-small-only hide-for-medium-min show-for-medium-portrait\">\n		<i class=\"yodlee-font-icon svg_info info y-tooltip center\" tooltip-width=\"250\" tooltip-title=\"";
  stack1 = "site_login_more_help_text";
  stack2 = {};
  foundHelper = helpers.loginUrl;
  stack3 = foundHelper || depth0.loginUrl;
  stack2['_SITE_LOGIN_URL_'] = stack3;
  foundHelper = helpers.containers;
  stack3 = foundHelper || depth0.containers;
  stack2['_CONTAINERS_'] = stack3;
  foundHelper = helpers.__;
  stack3 = foundHelper || depth0.__;
  tmp1 = {};
  tmp1.hash = stack2;
  if(typeof stack3 === functionType) { stack1 = stack3.call(depth0, stack1, tmp1); }
  else if(stack3=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, tmp1); }
  else { stack1 = stack3; }
  buffer += escapeExpression(stack1) + "\" mouseleave=\"false\" tabindex=\"0\" role=\"button\" aria-label=\"site login information\"></i>\n	</div>	\n</div>			\n";
  return buffer;});
templates['siteLoginForm'] = template(function (Handlebars,depth0,helpers,partials,data) {
  helpers = helpers || Handlebars.helpers;
  var buffer = "", stack1, stack2, stack3, stack4, foundHelper, tmp1, self=this, functionType="function", helperMissing=helpers.helperMissing, undef=void 0, escapeExpression=this.escapeExpression, blockHelperMissing=helpers.blockHelperMissing;

function program1(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n			<div class=\"globalError\" id=\"global_error\" tabindex=\"0\">";
  stack1 = "invalid_credentails";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</div>\n		";
  return buffer;}

function program3(depth0,data) {
  
  var buffer = "", stack1;
  buffer += "\n			<div class=\"globalError hide\" id=\"global_error\"></div>\n			<div class=\"helpText\">\n				<div>";
  foundHelper = helpers.siteLevelHelpText;
  stack1 = foundHelper || depth0.siteLevelHelpText;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "siteLevelHelpText", { hash: {} }); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "</div>\n				<div>";
  foundHelper = helpers.loginLevelHelpText;
  stack1 = foundHelper || depth0.loginLevelHelpText;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "loginLevelHelpText", { hash: {} }); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "</div>\n			</div>\n		";
  return buffer;}

function program5(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n	";
  foundHelper = helpers.accountCredentailForms;
  stack1 = foundHelper || depth0.accountCredentailForms;
  stack2 = helpers['if'];
  tmp1 = self.program(6, program6, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n";
  return buffer;}
function program6(depth0,data) {
  
  var buffer = "", stack1, stack2, stack3;
  buffer += "\n		<div class=\"row collapse\">\n			<div class=\"small-12 medium-min-single-col medium-portrait-7 medium-7 medium-portrait-offset-4 medium-offset-4 column\">\n				<div class=\"addedSiteCredentails\">\n					<div class=\"site\">";
  stack1 = "alread_added_accounts";
  stack2 = {};
  foundHelper = helpers.displayName;
  stack3 = foundHelper || depth0.displayName;
  stack2['_SITE_NAME_'] = stack3;
  foundHelper = helpers.__;
  stack3 = foundHelper || depth0.__;
  tmp1 = {};
  tmp1.hash = stack2;
  if(typeof stack3 === functionType) { stack1 = stack3.call(depth0, stack1, tmp1); }
  else if(stack3=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, tmp1); }
  else { stack1 = stack3; }
  buffer += escapeExpression(stack1) + "</div>\n					<ul class=\"accounts\">\n						";
  foundHelper = helpers.accountCredentailForms;
  stack1 = foundHelper || depth0.accountCredentailForms;
  stack2 = helpers.each;
  tmp1 = self.program(7, program7, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n					</ul>\n				</div>\n			</div>\n		</div>\n	";
  return buffer;}
function program7(depth0,data) {
  
  var buffer = "", stack1, stack2, stack3;
  buffer += "			\n					  		<li class=\"\"> ";
  stack1 = "account_with_login_id";
  stack2 = {};
  foundHelper = helpers.userId;
  stack3 = foundHelper || depth0.userId;
  stack2['_USER_ID_'] = stack3;
  foundHelper = helpers.__;
  stack3 = foundHelper || depth0.__;
  tmp1 = {};
  tmp1.hash = stack2;
  if(typeof stack3 === functionType) { stack1 = stack3.call(depth0, stack1, tmp1); }
  else if(stack3=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, tmp1); }
  else { stack1 = stack3; }
  buffer += escapeExpression(stack1) + " </li>\n						";
  return buffer;}

function program9(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n			";
  foundHelper = helpers.mfaQuestionsAndAnswers;
  stack1 = foundHelper || depth0.mfaQuestionsAndAnswers;
  stack2 = helpers.each;
  tmp1 = self.program(10, program10, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n		";
  return buffer;}
function program10(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n				<div class=\"row collapse\">\n					<div class = \"small-12 medium-portrait-3 medium-3 medium-min-single-col medium-portrait-offset-1 medium-offset-1 column\">\n						<label for=\"mfaAnswer_";
  stack1 = depth0.mfaQuestionAnswerId;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "this.mfaQuestionAnswerId", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\">";
  stack1 = depth0.mfaQuestion;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "this.mfaQuestion", { hash: {} }); }
  buffer += escapeExpression(stack1) + "</label>\n					</div>\n					<div class = \"small-12 medium-portrait-7 medium-7 medium-min-single-col column end\">\n						<input type=\"password\" autocomplete=\"off\" autocapitalize=\"off\" name=\"mfaAnswer_";
  stack1 = depth0.mfaQuestionAnswerId;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "this.mfaQuestionAnswerId", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" id=\"mfaAnswer_";
  stack1 = depth0.mfaQuestionAnswerId;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "this.mfaQuestionAnswerId", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" value=\"*****\" class=\"formField star_field password\"\n						";
  stack1 = depth0.maximumLength;
  stack2 = helpers['if'];
  tmp1 = self.program(11, program11, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n						";
  stack1 = depth0.minimumLength;
  stack2 = helpers['if'];
  tmp1 = self.program(13, program13, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n						/>\n					</div>	\n				</div>\n			";
  return buffer;}
function program11(depth0,data) {
  
  var buffer = "", stack1;
  buffer += "\n							maxlength=\"";
  stack1 = depth0.maximumLength;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "this.maximumLength", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\"\n						";
  return buffer;}

function program13(depth0,data) {
  
  var buffer = "", stack1;
  buffer += "\n							minlength=\"";
  stack1 = depth0.minimumLength;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "this.minimumLength", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\"\n						";
  return buffer;}

function program15(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n			<div class=\"row collapse\">\n				<div class=\"small-12 medium-portrait-7 medium-7 medium-min-single-col large-7 medium-portrait-offset-4 medium-offset-4 column\">\n					<input type=\"checkbox\" class=\"agreeTerms formField star_field\" value=\"Next\" />&nbsp;\n					<span class=\"termsOfService\">";
  stack1 = "terms_and_condition";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</span>\n				</div>\n			</div>\n			<div class=\"row collapse\">\n				<div class=\"small-12 medium-portrait-7 medium-7 medium-min-single-col medium-portrait-offset-4 medium-offset-4 column terms\">\n					<div class=\"loader hide large-4 right small-12\">\n						<img src=\"../../../img/loader.gif\" alt=\"loading\" title=\"loading\" />\n					</div>\n					<div class=\"termsOfCondtn hide\">\n						<div class=\"closeBtn hide text-right large-12 small-12\">X</div>\n						<div id=\"\" class=\"termsCondition\">\n							<h3>Yodlee - Privacy Policy</h3>\n							<p class=\"subTitle\">Yodlee is committed to safeguarding your privacy.</p>\n							<p class=\"subTitle\">Last Updated: 02/05/2014</p>\n							<p class=\"tOservicecontent\">Financial institutions trust Yodlee to power online banking applications that increase profitability and drive more value from the online channel. Yodlee’s personal financial management, payments, and customer acquisition solutions deliver a simple, centralized and secure means for consumers to manage all of their financial tasks – anytime, anywhere. Yodlee makes financial institutions’ sites essential to their customers and generates new revenue opportunities. More than 600 financial institutions and portals today offer Yodlee-powered solutions to millions of customers worldwide.</p>\n						</div>\n					</div>\n				</div>\n			</div>\n		";
  return buffer;}

function program17(depth0,data) {
  
  var stack1, stack2;
  stack1 = "update_btn_label";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  return escapeExpression(stack1);}

function program19(depth0,data) {
  
  var stack1, stack2;
  stack1 = "next_btn_label";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  return escapeExpression(stack1);}

  buffer += "<div class=\"row collapse\">\n	<div class=\"small-12 medium-min-single-col medium-portrait-7 medium-7 medium-portrait-offset-4 medium-offset-4 column\">\n		";
  foundHelper = helpers.invalidCredentails;
  stack1 = foundHelper || depth0.invalidCredentails;
  stack2 = helpers['if'];
  tmp1 = self.program(1, program1, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.program(3, program3, data);
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n	</div>\n</div>\n\n";
  stack1 = "true";
  stack2 = "==";
  stack3 = "added_sites_with_credentails";
  foundHelper = helpers.ifCond;
  stack4 = foundHelper || depth0.ifCond;
  tmp1 = self.program(5, program5, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  if(foundHelper && typeof stack4 === functionType) { stack1 = stack4.call(depth0, stack3, stack2, stack1, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack4, stack3, stack2, stack1, tmp1); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n\n<form autocomplete=\"off\">\n	<div class=\"loginForm\">\n		";
  foundHelper = helpers.components;
  stack1 = foundHelper || depth0.components;
  stack2 = {};
  foundHelper = helpers.showPassword;
  stack3 = foundHelper || depth0.showPassword;
  stack2['showPassword'] = stack3;
  foundHelper = helpers.showTypeEnabled;
  stack3 = foundHelper || depth0.showTypeEnabled;
  stack2['showTypeEnabled'] = stack3;
  foundHelper = helpers.reenterPasswordFieldEnabled;
  stack3 = foundHelper || depth0.reenterPasswordFieldEnabled;
  stack2['reenterPasswordFieldEnabled'] = stack3;
  foundHelper = helpers.loginForm;
  stack3 = foundHelper || depth0.loginForm;
  tmp1 = {};
  tmp1.hash = stack2;
  if(typeof stack3 === functionType) { stack1 = stack3.call(depth0, stack1, tmp1); }
  else if(stack3=== undef) { stack1 = helperMissing.call(depth0, "loginForm", stack1, tmp1); }
  else { stack1 = stack3; }
  buffer += escapeExpression(stack1) + "\n		";
  foundHelper = helpers.mfaQuestionsAndAnswers;
  stack1 = foundHelper || depth0.mfaQuestionsAndAnswers;
  stack2 = helpers['if'];
  tmp1 = self.program(9, program9, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n		";
  foundHelper = helpers.tncEnabled;
  stack1 = foundHelper || depth0.tncEnabled;
  stack2 = helpers['if'];
  tmp1 = self.program(15, program15, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n		<div class=\"row collapse\">\n			<div class = \"small-12 medium-portrait-7 medium-7 medium-min-single-col large-7 medium-portrait-offset-4 medium-offset-4 large-offset-4 column\">\n				<input class=\"button disabled primary expand\" type=\"submit\" value=\"";
  stack1 = "edit";
  foundHelper = helpers.flowType;
  stack2 = foundHelper || depth0.flowType;
  foundHelper = helpers.compare;
  stack3 = foundHelper || depth0.compare;
  tmp1 = self.program(17, program17, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.program(19, program19, data);
  if(foundHelper && typeof stack3 === functionType) { stack1 = stack3.call(depth0, stack2, stack1, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack3, stack2, stack1, tmp1); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\" aria-disabled=\"true\" />\n			</div>\n		</div>\n	</div>\n</form>";
  return buffer;});
return templates;
});
define('10003592_js/models/siteLoginForm',['10003592_js/common/dataParser'], function(DataParser) {
	var SiteLoginForm = Backbone.Model.extend({

        defaults: {
            components : '',
            siteLevelHelpText : '',
            loginLevelHelpText : '',
            siteId : '',
            tncEnabled : false,
            displayName : ''
        }

	});
	return SiteLoginForm;
});
define('10003592_js/views/siteLoginFormView',['10003592_js/compiled/finappCompiled', '10003592_js/models/siteLoginForm', '10003592_js/common/dataParser'], 

	function(templates, SiteLoginForm, DataParser) {

	var SiteLoginFormView = Backbone.Marionette.LayoutView.extend({



		model : SiteLoginForm,

		template: templates['siteLoginForm'],

		initialize: function(options) {

			this.siteInfo = options.siteInfo;
			this.siteAccountId = options.siteAccountId;
			this.tncEnabled = ( options.tncEnabled === true ) ? true : false;
			this.saving = false;
			this.moduleKey = options.moduleKey;
			this.flowType = options.flowType;

			if( options.errorCode == '402' ) {
            	this.model.set('invalidCredentails', true);
                options.errorCode = null;
            }

            if( this.model.get('loginLevelHelpText') && this.model.get('loginLevelHelpText').length <= 10 ) {
            	var helpText = Utilities.getString('default_login_help_text', { '_SITE_DISPLAY_NAME_' : this.siteInfo.displayName });
            	this.model.set('loginLevelHelpText', helpText);
            }

			this.model.set('siteId', this.siteInfo.siteId);
			this.model.set('siteLevelHelpText', this.siteInfo.siteLevelHelpText);
			this.model.set('isAlreadyAddedByUser', this.siteInfo.isAlreadyAddedByUser);
			//FIXME : change the name to populate password
			var showPassword = false;
			if(this.flowType == 'edit' || this.flowType == 'refresh'){
				showPassword = true;
				this.model.set('showTypeEnabled', false);
			} else {
				this.model.set('showTypeEnabled', Utilities.getParam('show_type_enabled'));
			}
			this.model.set('tncEnabled', this.tncEnabled );
			this.model.set('displayName', this.siteInfo.displayName );
			this.model.set('reenterPasswordFieldEnabled' , Utilities.getParam('reenter_password_field'));
			this.model.set('accountCredentailForms', options.accountCredentailForms);
			this.model.set('mfaQuestionsAndAnswers', options.mfaQuestionsAndAnswers);
			console.log(this.flowType, "--------==============++++++++++++++++");
			this.model.set('flowType', this.flowType);

			this.model.set('showPassword', showPassword);
		},

		events : {
			'click .tOs' : 'fetchTermsOfService',
			'click .closeBtn' : 'closeTermsFrame',
			'keyup input[type!="submit"]' : 'enableSubmitButton',
			'paste input[type!="sumbit"]' : 'enableButton',
			'cut input[type!="sumbit"]' : 'enableButton',
			'focus .password' : 'clearPasswordField',
			'click input.agreeTerms' : 'enableSubmitButton',
			'click .eyeIcon' : 'showHidePassword',
			'submit': 'addSiteAccount',
			'change input[type="radio"]' : 'showHideFields'
		},

		showHideFields : function(e) {
			var value = e.target.value;
			this.$el.find('.choiceField').addClass('hide');
			this.$el.find('#row_'+value).removeClass('hide');
			this.enableButton();
		},

		enableButton : function() {
			var self = this;
			setTimeout(function() {
				self.enableSubmitButton();
			}, 4);
		},

		onShow : function() {
			this.enableSubmitButton();
			this.$el.find('.globalError').focus();
			$(document).foundation();
			yo.customRadio();
			yo.customDropdown();
		},

		clearPasswordField : function( e ) {
			var value = e.target.value;
			if( $.trim(value) == '*****' ) {
				e.target.value = '';
				this.enableSubmitButton();
			}
		},

		enableSubmitButton : function() {
			var enabledButton = this.validateFormFields( false );
			if(enabledButton) {
				$(".site-form .button").removeClass("disabled");
				$(".site-form .button").prop("disabled","");
				$(".site-form .button").removeAttr('aria-disabled');
			} else {
				$(".site-form .button").addClass("disabled");
				$(".site-form .button").prop("disabled","disabled");
				$(".site-form .button").attr('aria-disabled','true');
			}
		},

		validateFormFields : function( reenterValidation ) {
			var enabledButton = 1;
			var formObj = this.$el.find(".loginForm");
			var enabledButton = LoginFormBuilder.validateLoginFormFields( formObj, reenterValidation );
            Logger.debug('Enable Button : '+enabledButton);
			return enabledButton;
	    },

		addSiteAccount : function(e) {
			e.preventDefault();
			this.$el.find('.globalError').addClass('hide');
			var self = this;
			if (this.validateFormFields( true ) === 1 && !this.saving) {

				yo.closeBubbleTooltip();
				var data = { 'siteInfo' : this.siteInfo };
				Logger.debug('ModuleKey : '+this.moduleKey);
				var formFieldMap = {};
				var formFields = this.$el.find('.formField');
				$.each(formFields, function(key, val) {
					var element = $(val);
					if( element.prop('type').toLowerCase() == 'radio') {
                		if(element.is(':checked')) {
                			formFieldMap[element.attr('name')] = element.val();
                		}
                	} else {
						formFieldMap[element.attr('name')] = ((Utilities.getParam('encrypt_data')) ? PKI.encrypt(element.val()) : element.val()); //encrypting only the form fieldselement.val();
					}
				});
				var result = DataParser.getSiteLoginFormPostData(this.model.get('components')
						, formFieldMap, this.model.get('siteId')
						, this.siteAccountId, this.model.get('mfaQuestionsAndAnswers'));

				var apiInfo = Application.Wrapper.getAPIDetails(result); 
				this.model.save(null, {
					type: apiInfo.method,
					url : apiInfo.url,
					data: apiInfo.data,
					beforeSend : function() {
						self.$el.find('#next').val(Utilities.getString('processing_text'));
						this.saving = true;
					},
					success: function(model, response) {
						var siteRefreshInfo = response.siteRefreshInfo;
						if( siteRefreshInfo && siteRefreshInfo.siteRefreshStatus 
							&& siteRefreshInfo.siteRefreshStatus.siteRefreshStatusId == '1' ) {
							if( self.tncEnabled ) {
								Utilities.setMemPrefvalue('externalAccTncRevision', Utilities.getParam('site_tnc_version'));
							}
							var data = { siteInfo : self.siteInfo, siteRefreshInfo : siteRefreshInfo, flowType : self.flowType }
							data.siteAccountId = response.siteAccountId;
							Application.Mediator.trigger('ADDED_SITE_ACCOUNT', data)
							Application.AppRouter.route( self.moduleKey, 'loadSiteRefreshStatusModule', true, data);
						} else {
							self.$el.find('#global_error').removeClass('hide').html(Utilities.getString('tech_diff_error'));
						}
					}, 
					error: function(model, error) {
						self.$el.find('#global_error').removeClass('hide').removeClass(Utilities.getString('tech_diff_error'));
						Logger.error(error);						
					},
					complete : function() {
						this.saving = false;
						self.$el.find('#next').val(Utilities.getString('next_btn_label'));
					}
				})                  			
			}
			return false;
		},

		fetchTermsOfService : function(){
			/*var element;
			$(".loader").removeClass("hide");
			element = document.createElement("iframe");
			element.setAttribute('id', "");
			element.setAttribute('src', "./terms.html");
			element.setAttribute('class', "termsCondition small-12 large-6 right columns");
			$(".termsOfCondtn").append(element);   

			if($(".termsOfCondtn").find(".termsCondition")){
				$(".closeBtn").removeClass("hide");
				$(".loader").addClass("hide");
			}*/

			$(".closeBtn, .termsOfCondtn").toggle();
			$(".closeBtn, .termsOfCondtn").removeClass("hide");

		},

		closeTermsFrame : function(){
			$(".termsOfCondtn, .closeBtn").toggle();
			$(".closeBtn, .termsOfCondtn").removeClass("hide");
		},

		showHidePassword : function(event){
			var inputField = this.$el.find("input.password");
			if(Utilities.toggleInputTypes(inputField)){
				$(".eyeIcon").removeClass("open");
				$(".eyeIcon").removeClass("svg_pass-open");
				$(".eyeIcon").addClass("svg_pass-close");
				$(".eyeIcon").attr('aria-label', Utilities.getString('unmasked_text'));
			}else{
				$(".eyeIcon").addClass("open");
				$(".eyeIcon").removeClass("svg_pass-close");
				$(".eyeIcon").addClass("svg_pass-open");
				$(".eyeIcon").attr('aria-label', Utilities.getString('masked_text'));
			}

		}
	});
	return SiteLoginFormView;
});

define('10003592_js/models/header',[], function() {
    var Header = Backbone.Model.extend({
        defaults : {
            displayName : '',
            baseUrl : '',
            loginUrl : '',
            siteId : 0,
            siteLevelHelpText : ''
        }
    });
    return Header;
});
define('10003592_js/views/headerView',['10003592_js/compiled/finappCompiled'], function(templates) {
	var Header = Marionette.ItemView.extend({

		template: templates['header'],

		events : {
			'click .popwin' : 'openNewWindow'
		},
		templateHelpers : {
			getStatus : function(){
				var message = "";
				if(this.flowType == 'edit'){
					message = Utilities.getString('status_edited')
				} else if(this.flowType == 'edit'){
					message = Utilities.getString('status_updated')
				} else {
					message = Utilities.getString('status_added')
				} 
				return message;
			}
		},

		onShow : function() {
			var self = this;
			this.$el.find('#siteLogoDiv img').on('load', function() { self.showHideSiteName() });
			yo.bubbleTooltip();
		},

		showHideSiteName : function() {
			this.$el.find('#siteLogoDiv').show();
			this.$el.find('#siteLogoDisplayName').hide();
		},

		openNewWindow : function(event) {
			event.preventDefault ? event.preventDefault() : event.returnValue = false;
			var currentElement = $(event.target);
	  		var url = currentElement.prop("href");
	  		Application.Wrapper.openPopupWindow(url);
	  		return false;
	  	}		

	})
	return Header;
});
define('10003592_js/views/baseLayoutView',[
    '10003592_js/compiled/finappCompiled',
    '10003592_js/models/header',
    '10003592_js/views/headerView',
    ], 
    function(
        templates, 
        HeaderModel,
        HeaderView) {
        var BaseLayoutView = Backbone.Marionette.LayoutView.extend({

            className: 'site-form',

            initialize: function (options) {
                this.headerModel = new HeaderModel(options.siteInfo);
                this.templateHelpers.flowType = options.flowType;

            },

            template: templates['baseLayout'],
            regions: {
              header: "#header",
              content: "#content",
            },
            templateHelpers : {
                showBreadCrumb : function() {
                    if( Utilities.getParam('show_breadcrumb') == 'true' || Utilities.getParam('show_breadcrumb') === true ) {
                        if( this.flowType != 'edit' && this.flowType != 'refresh' ) {
                            return true;
                        }
                    }
                    return false;
                } 
            },
            onShow : function() {
                var headerView = new HeaderView({ model : this.headerModel });
                this.header.show(headerView);
            }
        });
        return BaseLayoutView;
});
define('10003592_js/views/errorView',[
    '10003592_js/compiled/finappCompiled'
    ], 
    function(templates) {
        var ErrorView = Backbone.Marionette.LayoutView.extend({

            className: 'error-view',

            initialize: function (options) {
                
            },

            template: templates['error'],

            onShow : function() {

            }
        });
        return ErrorView;
});
define('10003592_js/models/errorModel',[], function() {
  	var ErrorModel = Backbone.Model.extend({
	    defaults : {
	    	errorDescription: ""
	    },

	    initialize : function( options ) {
	    	Logger.debug('DEBUG : Error Model initialized.');
    	}
  	});
  	
  	return ErrorModel;
});
define('10003592_js/controller/siteLoginFormController',[
		'10003592_js/models/siteAccount'
		,'10003592_js/views/siteLoginFormView'
		,'10003592_js/models/siteLoginForm'
		,'10003592_js/views/baseLayoutView'
		,'10003592_js/views/errorView'
		,'10003592_js/models/errorModel'
		, '10003592_js/common/dataParser'
	], function(SiteAccount, SiteLoginFormView, SiteLoginForm, BaseLayoutView, ErrorView, ErrorModel, DataParser) {

	var SiteLoginFormController = Backbone.Marionette.Controller.extend({

		initialize: function(options) {

			Logger.debug('Site Login Form Controller is initialized.');

  		},

		start: function(options) {
			var self = this;
			if( !options.data ) {
				options.data = {};
			}
			// options.data = { siteInfo : {}, flowType : 'edit', siteAccountId : 10003000};


			this.tncEnabled = ( Utilities.getParam('site_tnc_enabled') && Utilities.getParam('site_tnc_version') > 0 );
			this.region = options.region;
			yo.inlineSpinner.show( this.region.el );

			this.siteInfo = options.data.siteInfo;
			if( this.siteInfo ) {
				this.siteId = this.siteInfo.siteId;
				this.errorCode = options.data.errorCode;
				this.isAlreadyAdded = this.siteInfo.isAlreadyAddedByUser;
				this.mfaEnabled = false;
				this.siteAccountId = options.data.siteAccountId;
				this.flowType = options.data.flowType;
		        if(this.flowType == 'edit' || this.flowType == 'refresh') {
		          this.mfaEnabled = true;
		        }
				this.getGraphData();
			} else {
				this.mfaEnabled = false;
				this.isAlreadyAdded = false;
				this.flowType = options.data.flowType;

				if(!this.flowType){
                    Logger.error('Site Login Controller : Flow Type is not found.');
					var errormodel = new ErrorModel({ errorDescription : Utilities.getString('error_flowtype_not_found') });
                    self.errorView = new ErrorView({
                    	moduleKey : self.moduleKey, 
						model : errormodel
                    });
					options.region.show(this.errorView);
					return;
				} 

				this.siteAccountId = options.params.siteAccountId || options.data.siteAccountId;
				this.validateMemSiteAccount();
			}
		},


		validateMemSiteAccount : function(){
			var self = this;

			if(!this.siteAccountId || isNaN(Number(this.siteAccountId)) || !this.siteAccountId > 0){
                Logger.error('Site Login Controller : Site Account Id is not found.');
				var errormodel = new ErrorModel({ errorDescription : Utilities.getString('error_site_id_not_found') });
                self.errorView = new ErrorView({
                	moduleKey : self.moduleKey, 
					model : errormodel
                });
				this.region.show(this.errorView);
			} else { 
				var self = this;
	        	var result = DataParser.getSiteAccountsInputData(this.siteAccountId);
	        	var apiInfo = Application.Wrapper.getAPIDetails(result); 
	        	this.siteAccount = new SiteAccount({moduleKey : this.moduleKey});
	        	Logger.debug(this.siteRefreshStatus);
	        	this.siteAccount.fetch({
	                type: apiInfo.method,
	                url : apiInfo.url,
	                data: apiInfo.data,
	                context : this,
	                success : function(model, response) {
						self.siteInfo = model.get('siteInfo');
						//FIXME : Currently mfaType is not coming from the API
						//if(model.get('siteInfo').mfaTypeId == 4 || model.get('siteInfo').mfaTypeId == 5 ){
							self.mfaEnabled = true;
						//}
						self.isAlreadyAdded = model.get('siteInfo').isAlreadyAddedByUser;
						self.getGraphData();
					},
	                error: function(model, error) {
	                    Logger.error('Getting error while fetching siteaccount data : '+error);
	                    var errormodel = new ErrorModel({ errorDescription : Utilities.getString('tech_diff_update_account') });
		                self.errorView = new ErrorView({
		                	moduleKey : self.moduleKey, 
							model : errormodel
		                });
						self.region.show(self.errorView);
	                },
	                complete : function() {
	  	               // yo.inlineSpinner.hide( self.baseLayoutView.content.el );
	                }
	            });
	        }

		},

		getGraphData : function() {
			Logger.debug("Calling graph data for SiteLoginForm View.");
			var self = this;
        	var graphData = DataParser.getGraphInputData(this.siteId, this.siteAccountId, this.tncEnabled, this.mfaEnabled, this.isAlreadyAdded);
        	graphData = Application.Wrapper.formatGraphInputData(graphData); 
        	Application.YGraph.build( graphData, function( response ) {
				self.checkTncEnabled(response['']);
				var loginFormData = response['InternalPassThroughMakeCall_siteAccountCredentails'] || response['InternalPassThroughMakeCall_siteLoginForm']
				self.showSiteLoginFormView(loginFormData
						, response['InternalPassThroughMakeCall_siteAccountCredentailForms']
						, response['InternalPassThroughMakeCall_siteAccountMfaQuestionsAndAnswers']);

				//response from DataEncryptionService Call to get the public key
				if(response["InternalPassThroughMakeCall_getPublicKey"]) {
					PKI.setKey(response["InternalPassThroughMakeCall_getPublicKey"]);
				}
        	});
		},


		checkTncEnabled : function( results ) {
			if( this.tncEnabled ) {
				var acceptedTncVersion = ( results && results.values ) ? results.values[0] : 0;
				Logger.debug('Accepted Version : '+acceptedTncVersion);
				this.tncEnabled = ( Utilities.getParam('site_tnc_version') == acceptedTncVersion ) ? false : true;
			}
		},

		showSiteLoginFormView : function( loginForm, credentailForms, mfaQuestionsAndAnswers) {
			Logger.debug('Show Site login form view method is called');

			yo.inlineSpinner.hide(this.region.el);

			this.baseLayout = new BaseLayoutView({ siteInfo : this.siteInfo, flowType : this.flowType });
			this.region.show(this.baseLayout);
			var siteLoginForm = new SiteLoginForm();
			siteLoginForm.set(DataParser.parseSiteLoginForm(loginForm));

			var accountCredentailForms = DataParser.parseSiteAccountCredentailForms( credentailForms );

			var siteLoginFormView = new SiteLoginFormView(
					{
						model: siteLoginForm, 
						moduleKey : this.moduleKey, 
						siteInfo : this.siteInfo,
						siteAccountId : this.siteAccountId, 
						tncEnabled : this.tncEnabled,
						errorCode : this.errorCode,
						accountCredentailForms: accountCredentailForms,
						mfaQuestionsAndAnswers : mfaQuestionsAndAnswers,
						flowType : this.flowType
					});
			this.baseLayout.content.show( siteLoginFormView );
		}
	});
	return SiteLoginFormController;
});
define('10003592_js/finapp',['10003592_js/controller/siteLoginFormController'], function(SiteLoginFormController) {
	var module = Application.Appcore.Module.extend({
		controller : SiteLoginFormController,

		initialize : function(options) {

		}	

	});
	return module;
});

