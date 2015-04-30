define('10003593_js/finappConfig',[],function(){ return ({
}) });
define('10003593_js/common/dataParser',[], function() {
    
	var DataParser = function() {
		var SITE_REFRESH_INFO_API = 'siteRefreshInfo';
		var GET_SITE_MFA_RESPONSE_API = "getMFASiteResponse";
		var PUT_SITE_MFA_RESPONSE_API = "putMFASiteResponse";
		var STOP_SITE_REFRESH_API = 'stopSiteRefresh';
		var START_SITE_REFRESH_API = 'startSiteRefresh';
		var ACCOUNTS_FOR_SITE_API = "siteAccountByMemSiteAccId";

		var _parseSiteRefreshStatus = function( response ) {
			var result = {};
			if( response && response.siteRefreshStatus ) {
				result.siteRefreshStatusId = response.siteRefreshStatus.siteRefreshStatusId;
				result.siteRefreshMode = response.siteRefreshMode;
				result.errorCode = response.code;
				if( response.siteAccountId ) {
					result.siteAccountId = response.siteAccountId;
				}

				if( response.suggestedFlow ) {
					result.suggestedFlow = response.suggestedFlow;
				}

				if(response.suggestedFlowReason){ 
	        		result.suggestedFlowReason = response.suggestedFlowReason;
	        	}
			}
			return result;
		};

		var _parseMFAResponse = function( response ) {
			var result = {};
			if( response.fieldInfo ) {
				result.fieldInfo = response.fieldInfo;
				result.mfaType = response.fieldInfo.mfaFieldInfoType;
				if( response.fieldInfo.mfaFieldInfoType == 'SECURITY_QUESTION') {
					if( response.fieldInfo.questionAndAnswerValues.length > 0 ) {
                		
                		for(var i=0; i<response.fieldInfo.questionAndAnswerValues.length; i++) {
                			if( i == 0 ) {
                				response.fieldInfo.questionAndAnswerValues[0].first = true;
                			}
                			if(response.fieldInfo.questionAndAnswerValues[i].maximumLength < 0) {
                				response.fieldInfo.questionAndAnswerValues[i].maximumLength = 0;
                			}
                			if(response.fieldInfo.questionAndAnswerValues[i].minimumLength < 0) {
                				response.fieldInfo.questionAndAnswerValues[i].minimumLength = 0;
                			}
                		}
                	}
            	} else if( response.fieldInfo.mfaFieldInfoType == 'TOKEN_ID'
            			|| response.fieldInfo.mfaFieldInfoType == 'IMAGE') {
            		if(response.fieldInfo.maximumLength < 0) {
            			response.fieldInfo.maximumLength = 0;
            		}
            		if(response.fieldInfo.minimumLength < 0) {
            			response.fieldInfo.minimumLength = 0;
            		}
            	}
			}

			if( response.timeOutTime > 0 ) {
				result.timeOutTime = Math.floor(response.timeOutTime/1000);	
			}
			
			result.retry = response.retry;
			result.isMessageAvailable = response.isMessageAvailable;
			result.siteAccountId = response.memSiteAccId;
			result.errorCode = response.errorCode;
			result.imageId = response.imageId;

			return result;
		};

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
				siteInfo.mfaType = _siteInfo.mfaType;
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
	        	siteInfo.suggestedFlow = _siteInfo.suggestedFlow;

	        	//siteInfo.mfaTypeId = _siteInfo.mfaType.typeId;
	        	result.siteRefreshInfo = response.siteRefreshInfo;
	        	result.siteInfo = siteInfo;
	        	result.siteAccountId = response.siteAccountId;
				return result;
			}
			return result;
		};

		var _getSiteAccountsInputData = function(siteAccountId) {
			var result = {};
			result.method = 'POST';
			result.data = {'siteAccountFilter.memSiteAccIds[0]' : '' + siteAccountId + '', 'notrim' : 'true' };
			result.apiUrl = ACCOUNTS_FOR_SITE_API;
			return result;	
		};	

		var _getStartSiteRefreshInputData = function( siteAccountId, siteRefreshMode ) {
			var result = {};
			result.method = 'POST';
			result.data = {};
			result.data['memSiteAccId'] = ''+siteAccountId+'';
			result.data['refreshParameters.refreshPriority'] = '1';
			result.data['refreshParameters.refreshMode.refreshModeId'] = ''+siteRefreshMode.refreshModeId+'';
			result.data['refreshParameters.refreshMode.refreshMode'] = siteRefreshMode.refreshMode;
			result.apiUrl = START_SITE_REFRESH_API;
			return result;			
		}

		var _getSiteRefreshInfoInputData = function(siteAccountId)	{
			var result = {};
			result.method = 'POST';
			result.data = {'memSiteAccId' : siteAccountId };
			result.apiUrl = SITE_REFRESH_INFO_API;
			return result;			
		}

		var _getMFAResponseForSite = function(siteAccountId) {
			var result = {};
			result.method = 'POST';
			result.data = {'memSiteAccId' : siteAccountId };
			result.apiUrl = GET_SITE_MFA_RESPONSE_API;
			return result;						
		}



		var _getMFASecurityQuestionPostData = function( jsonData, formFieldMap, siteAccountId ) {
			var result = {};
        	result.method = 'POST';
        	result.apiUrl = PUT_SITE_MFA_RESPONSE_API;
        	result.data = _convertToServerJson( jsonData.questionAndAnswerValues, 'userResponse.quesAnsDetailArray', formFieldMap);
			result.data['memSiteAccId'] = siteAccountId;
			result.data['userResponse.objectInstanceType'] = 'com.yodlee.core.mfarefresh.MFAQuesAnsResponse';
        	return result;
		}

		var _getMFATokenPostData = function( jsonData, formFieldMap, siteAccountId ) {
			var result = {};
        	result.method = 'POST';
        	result.apiUrl = PUT_SITE_MFA_RESPONSE_API;
        	result.data = {};
			result.data['memSiteAccId'] = siteAccountId;
			result.data['userResponse.objectInstanceType'] = 'com.yodlee.core.mfarefresh.MFATokenResponse';
			result.data['userResponse.token'] = formFieldMap['token'];
        	return result;
		}

		var _getMFACaptchaTokenPostData = function( jsonData, formFieldMap, siteAccountId ) {
			var result = {};
        	result.method = 'POST';
        	result.apiUrl = PUT_SITE_MFA_RESPONSE_API;
        	result.data = {};
			result.data['memSiteAccId'] = siteAccountId;
			result.data['userResponse.objectInstanceType'] = 'com.yodlee.core.mfarefresh.MFAImageResponse';
			result.data['userResponse.imageString'] = formFieldMap['imageString'];
        	return result;
		}

		var _getStopSiteRefreshInputData = function( siteAccountId, reasonId ) {
			var result = {};
        	result.method = 'POST';
        	result.apiUrl = STOP_SITE_REFRESH_API;	
        	result.data = {};		
			result.data['memSiteAccId'] = ''+siteAccountId+'';
			result.data['reason'] = ''+reasonId+'';
			return result;
		}

		var _convertToServerJson = function(obj, prefix, inputVals, map) {
			if( !map ) { map = {} };
			if( Object.prototype.toString.call(obj) == "[object Array]" ) {
				var j;
				for(j=0;j<obj.length;j++) {
					_convertToServerJson(obj[j], prefix + '[' + j +']', inputVals, map);
				}
			} else if( typeof obj == 'object' ) {
				var key;
				for(key in obj) {
					if( key == 'sequence' || key == 'first' ) {
						continue;
					}
					if( key == 'metaData' ) {
						_convertToServerJson(inputVals[obj[key]], prefix + '.answer', inputVals, map);
					}
					if( key == 'responseFieldType' ) {
						_convertToServerJson(obj[key], prefix + '.answerFieldType', inputVals, map);	
					} else {
						_convertToServerJson(obj[key], prefix + '.' + key, inputVals, map);
					}
				}
				
			} else {
				map[prefix] = ''+obj+'';
			}
			return map;
		 }

		return {
			parseSiteAccount : _parseSiteAccount,
	        parseSiteRefreshStatus: _parseSiteRefreshStatus,
	        parseMFAResponse : _parseMFAResponse,
	        getSiteRefreshInfoInputData : _getSiteRefreshInfoInputData,
	       	getMFAResponseForSite : _getMFAResponseForSite,
	        getMFASecurityQuestionPostData : _getMFASecurityQuestionPostData,
	        getMFATokenPostData : _getMFATokenPostData,
	        getMFACaptchaTokenPostData : _getMFACaptchaTokenPostData,
	        getStopSiteRefreshInputData : _getStopSiteRefreshInputData,
	        getStartSiteRefreshInputData : _getStartSiteRefreshInputData,
	       	getSiteAccountsInputData : _getSiteAccountsInputData
	    };

	}
	return new DataParser();
});

define('10003593_js/models/siteAccount',['10003593_js/common/dataParser'], function(DataParser) {
	var SiteAccount = Backbone.Model.extend({

		parse : function(response) {
			return DataParser.parseSiteAccount(response);
		}
	});
  return SiteAccount;
});
define('10003593_js/models/siteRefreshStatus',['10003593_js/common/dataParser'], function(DataParser) {
    var SiteRefreshStatus = Backbone.Model.extend({
        defaults : {
            message: '',
            errorCode: 0,
            siteRefreshStatusId : -1,
            siteRefreshModeId : -1,
            siteAccountId : 0
        },

        initialize : function(options) {
        	console.log('Model intiated.');
        	console.log(options);
        },

        parse : function( response ) {
            return DataParser.parseSiteRefreshStatus(response);
        }

    });
    return SiteRefreshStatus;
});
define('10003593_js/models/MFASecurity',['10003593_js/common/dataParser'], function(DataParser) {
    var MFASecurity = Backbone.Model.extend({
        defaults: {
            message : '',
            timeOutTime : 0,
            fieldInfo : null,
            isMessageAvailable : false,
            retry : false,
            errorCode : 0
        },

        parse : function(response) {
        	return DataParser.parseMFAResponse(response);
        }

    });
    return MFASecurity;
});
define('10003593_js/models/errorModel',[], function() {
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

define('10003593_js/compiled/finappCompiled',['handlebars'], function(Handlebars) {
  var template = Handlebars.template, templates = Handlebars.templates = Handlebars.templates || {};
templates['baseLayout'] = template(function (Handlebars,depth0,helpers,partials,data) {
  helpers = helpers || Handlebars.helpers;
  var buffer = "", stack1, stack2, foundHelper, tmp1, self=this, functionType="function", helperMissing=helpers.helperMissing, undef=void 0, escapeExpression=this.escapeExpression;

function program1(depth0,data) {
  
  var buffer = "", stack1, stack2, stack3;
  buffer += "\n    	";
  stack1 = 3;
  stack2 = 2;
  foundHelper = helpers.breadcrumb;
  stack3 = foundHelper || depth0.breadcrumb;
  if(typeof stack3 === functionType) { stack1 = stack3.call(depth0, stack2, stack1, { hash: {} }); }
  else if(stack3=== undef) { stack1 = helperMissing.call(depth0, "breadcrumb", stack2, stack1, { hash: {} }); }
  else { stack1 = stack3; }
  buffer += escapeExpression(stack1) + "\n    ";
  return buffer;}

  buffer += "<div>\n	";
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
templates['capcha'] = template(function (Handlebars,depth0,helpers,partials,data) {
  helpers = helpers || Handlebars.helpers;
  var buffer = "", stack1, stack2, foundHelper, tmp1, self=this, functionType="function", helperMissing=helpers.helperMissing, undef=void 0, escapeExpression=this.escapeExpression;

function program1(depth0,data) {
  
  
  return "\n					showType\n				";}

function program3(depth0,data) {
  
  var buffer = "", stack1;
  buffer += "\n					maxlength=\"";
  foundHelper = helpers.fieldInfo;
  stack1 = foundHelper || depth0.fieldInfo;
  stack1 = (stack1 === null || stack1 === undefined || stack1 === false ? stack1 : stack1.maximumLength);
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "fieldInfo.maximumLength", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\"\n				";
  return buffer;}

function program5(depth0,data) {
  
  var buffer = "", stack1;
  buffer += "\n					minlength=\"";
  foundHelper = helpers.fieldInfo;
  stack1 = foundHelper || depth0.fieldInfo;
  stack1 = (stack1 === null || stack1 === undefined || stack1 === false ? stack1 : stack1.minimumLength);
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "fieldInfo.minimumLength", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\"\n				";
  return buffer;}

function program7(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n					<a href=\"javascript:void(0)\"class=\"yodlee-font-icon svg_pass-close eyeIcon\"  aria-label=\"";
  stack1 = "unmasked_text";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\" role=\"button\"></a>\n				";
  return buffer;}

  buffer += "<form>\n	<div class=\"loginForm\">\n		<div class=\"row collapse\">\n			<div class = \"small-12 medium-portrait-7 medium-7 medium-min-single-col medium-portrait-offset-4 medium-offset-4 column collapse  \">\n				<div class=\"text-center captchaBox\">\n					<img src=\"";
  foundHelper = helpers.captchaImageUrl;
  stack1 = foundHelper || depth0.captchaImageUrl;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "captchaImageUrl", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\"/>\n				</div>\n			</div>\n		</div>	\n		<div class=\"row collapse\">\n			<div class = \"small-12 medium-portrait-3 medium-3 medium-min-single-col medium-portrait-offset-1 medium-offset-1 column\">\n				<label class=\"label\" for=\"imageString\">";
  foundHelper = helpers.fieldInfo;
  stack1 = foundHelper || depth0.fieldInfo;
  stack1 = (stack1 === null || stack1 === undefined || stack1 === false ? stack1 : stack1.displayString);
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "fieldInfo.displayString", { hash: {} }); }
  buffer += escapeExpression(stack1) + "</label>\n			</div>\n			<div class = \"small-12 medium-portrait-7 medium-7 medium-min-single-col column end\">\n				<input type =\"password\" autocomplete=\"off\" autocapitalize=\"off\" value=\"\" id=\"imageString\" name=\"imageString\" class=\"formField star_field input-error-field\n				";
  foundHelper = helpers.showTyping;
  stack1 = foundHelper || depth0.showTyping;
  stack2 = helpers['if'];
  tmp1 = self.program(1, program1, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n				\" \n				";
  foundHelper = helpers.fieldInfo;
  stack1 = foundHelper || depth0.fieldInfo;
  stack1 = (stack1 === null || stack1 === undefined || stack1 === false ? stack1 : stack1.maximumLength);
  stack2 = helpers['if'];
  tmp1 = self.program(3, program3, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n				";
  foundHelper = helpers.fieldInfo;
  stack1 = foundHelper || depth0.fieldInfo;
  stack1 = (stack1 === null || stack1 === undefined || stack1 === false ? stack1 : stack1.minimumLength);
  stack2 = helpers['if'];
  tmp1 = self.program(5, program5, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n				/>\n				";
  foundHelper = helpers.showTyping;
  stack1 = foundHelper || depth0.showTyping;
  stack2 = helpers['if'];
  tmp1 = self.program(7, program7, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n			</div>	\n		</div>\n		<div class=\"row timerRow collapse\">\n			<div class = \"small-12 medium-portrait-4 medium-4 medium-min-single-col medium-portrait-offset-4 medium-offset-4 column\">\n				<span class = \"timmer-cls\">";
  foundHelper = helpers.timeOutTime;
  stack1 = foundHelper || depth0.timeOutTime;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "timeOutTime", { hash: {} }); }
  buffer += escapeExpression(stack1) + " ";
  stack1 = "seconds_left";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</span>\n			</div>\n			<span aria-live=\"polite\" class=\"ada-offscreen\" id=\"timerSecLeft\">";
  foundHelper = helpers.timeOutTime;
  stack1 = foundHelper || depth0.timeOutTime;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "timeOutTime", { hash: {} }); }
  buffer += escapeExpression(stack1) + " ";
  stack1 = "seconds_left";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</span>\n		</div>\n		<div class=\"row collapse\">\n			<div class = \"small-12 medium-portrait-7 medium-7 medium-min-single-col medium-portrait-offset-4 medium-offset-4 column\">\n				<input class=\"primary button disabled expand\" type=\"submit\" value=\"";
  stack1 = "next_btn_label";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\" aria-disabled=\"true\" />\n			</div>\n		</div>\n	</div>\n</form>";
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
  buffer += "\n		<div id=\"siteLogoDisplayName\" class=\"siteDisplayName\">";
  foundHelper = helpers.displayName;
  stack1 = foundHelper || depth0.displayName;
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</div>				\n	</div>\n	<div class=\"small-12 medium-portrait-7 medium-7 medium-min-single-col column end\">\n		<div class=\"siteUrl\">\n			";
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
  buffer += "\n		</div>\n	</div>\n</div>			\n";
  return buffer;});
templates['securityKey'] = template(function (Handlebars,depth0,helpers,partials,data) {
  helpers = helpers || Handlebars.helpers;
  var buffer = "", stack1, stack2, foundHelper, tmp1, self=this, functionType="function", helperMissing=helpers.helperMissing, undef=void 0, escapeExpression=this.escapeExpression;

function program1(depth0,data) {
  
  
  return "\n					showType\n				";}

function program3(depth0,data) {
  
  var buffer = "", stack1;
  buffer += "\n					maxlength=\"";
  foundHelper = helpers.fieldInfo;
  stack1 = foundHelper || depth0.fieldInfo;
  stack1 = (stack1 === null || stack1 === undefined || stack1 === false ? stack1 : stack1.maximumLength);
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "fieldInfo.maximumLength", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\"\n				";
  return buffer;}

function program5(depth0,data) {
  
  var buffer = "", stack1;
  buffer += "\n					minlength=\"";
  foundHelper = helpers.fieldInfo;
  stack1 = foundHelper || depth0.fieldInfo;
  stack1 = (stack1 === null || stack1 === undefined || stack1 === false ? stack1 : stack1.minimumLength);
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "fieldInfo.minimumLength", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\"\n				";
  return buffer;}

function program7(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n					<a class=\"yodlee-font-icon svg_pass-close eyeIcon\" href=\"javascript:void(0)\" role=\"button\" aria-label=\"";
  stack1 = "unmasked_text";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\"></a>\n				";
  return buffer;}

  buffer += "<form>\n	<div class=\"loginForm\">\n		<div class=\"row collapse\">\n			<div class = \"small-12 medium-portrait-3 medium-3 medium-min-single-col medium-portrait-offset-1  medium-offset-1 column\">\n				<label class=\"label\" for=\"token\">";
  foundHelper = helpers.fieldInfo;
  stack1 = foundHelper || depth0.fieldInfo;
  stack1 = (stack1 === null || stack1 === undefined || stack1 === false ? stack1 : stack1.displayString);
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "fieldInfo.displayString", { hash: {} }); }
  buffer += escapeExpression(stack1) + "</label>\n			</div>\n			<div class = \"small-12 medium-portrait-7 medium-7 medium-min-single-col column end \">\n				<input type =\"password\" autocomplete=\"off\" autocapitalize=\"off\" value=\"\" id=\"token\" name=\"token\" class=\"formField star_field input-error-field\n				";
  foundHelper = helpers.showTyping;
  stack1 = foundHelper || depth0.showTyping;
  stack2 = helpers['if'];
  tmp1 = self.program(1, program1, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n				\" \n				";
  foundHelper = helpers.fieldInfo;
  stack1 = foundHelper || depth0.fieldInfo;
  stack1 = (stack1 === null || stack1 === undefined || stack1 === false ? stack1 : stack1.maximumLength);
  stack2 = helpers['if'];
  tmp1 = self.program(3, program3, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n				";
  foundHelper = helpers.fieldInfo;
  stack1 = foundHelper || depth0.fieldInfo;
  stack1 = (stack1 === null || stack1 === undefined || stack1 === false ? stack1 : stack1.minimumLength);
  stack2 = helpers['if'];
  tmp1 = self.program(5, program5, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n				 />\n				";
  foundHelper = helpers.showTyping;
  stack1 = foundHelper || depth0.showTyping;
  stack2 = helpers['if'];
  tmp1 = self.program(7, program7, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n			</div>	\n		</div>\n		<div class=\"row timerRow collapse\">\n			<div class = \"small-12 medium-portrait-3 medium-3 medium-min-single-col large-7 medium-portrait-offset-4 medium-offset-4 column\">\n				<span class = \"timmer-cls\">";
  foundHelper = helpers.timeOutTime;
  stack1 = foundHelper || depth0.timeOutTime;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "timeOutTime", { hash: {} }); }
  buffer += escapeExpression(stack1) + " ";
  stack1 = "seconds_left";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</span>\n			</div>\n			<span aria-live=\"polite\" class=\"ada-offscreen\" id=\"timerSecLeft\">";
  foundHelper = helpers.timeOutTime;
  stack1 = foundHelper || depth0.timeOutTime;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "timeOutTime", { hash: {} }); }
  buffer += escapeExpression(stack1) + " &nbsp; ";
  stack1 = "seconds_left";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</span>\n		</div>\n		<div class=\"row collapse\">\n			<div class = \"small-12 medium-portrait-7 medium-7 medium-min-single-col large-7 medium-portrait-offset-4 medium-offset-4 column\">\n				<input class=\"primary button disabled expand\" type=\"submit\" value=\"";
  stack1 = "next_btn_label";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\" aria-disabled=\"true\" />\n			</div>\n		</div>\n	</div>\n</form>\n";
  return buffer;});
templates['securityQuestions'] = template(function (Handlebars,depth0,helpers,partials,data) {
  helpers = helpers || Handlebars.helpers;
  var buffer = "", stack1, stack2, foundHelper, tmp1, self=this, functionType="function", helperMissing=helpers.helperMissing, undef=void 0, escapeExpression=this.escapeExpression;

function program1(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n			<div class=\"row collapse\">\n				<div class = \"small-12 medium-portrait-3 medium-3 medium-min-single-col medium-portrait-offset-1 medium-offset-1 column\">\n					<label class=\"label\" for=\"";
  stack1 = depth0.metaData;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "this.metaData", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\">";
  stack1 = depth0.question;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "this.question", { hash: {} }); }
  buffer += escapeExpression(stack1) + "</label>\n				</div>\n				<div class = \"small-12 medium-portrait-7 medium-7 medium-min-single-col column end\">\n					<input type=\"password\" autocomplete=\"off\" autocapitalize=\"off\" name=\"";
  stack1 = depth0.metaData;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "this.metaData", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" id=\"";
  stack1 = depth0.metaData;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "this.metaData", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" value=\"\" class=\"formField star_field input-error-field\n 					";
  foundHelper = helpers.first;
  stack1 = foundHelper || depth0.first;
  stack2 = helpers['if'];
  tmp1 = self.program(2, program2, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n					\"\n					";
  stack1 = depth0.maximumLength;
  stack2 = helpers['if'];
  tmp1 = self.program(5, program5, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n					";
  stack1 = depth0.minimumLength;
  stack2 = helpers['if'];
  tmp1 = self.program(7, program7, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n					/>\n					";
  foundHelper = helpers.first;
  stack1 = foundHelper || depth0.first;
  stack2 = helpers['if'];
  tmp1 = self.program(9, program9, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n				</div>	\n			</div>\n		";
  return buffer;}
function program2(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n						";
  foundHelper = helpers.showTyping;
  stack1 = foundHelper || depth0.showTyping;
  stack2 = helpers['if'];
  tmp1 = self.program(3, program3, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n					";
  return buffer;}
function program3(depth0,data) {
  
  
  return "\n							showType\n						";}

function program5(depth0,data) {
  
  var buffer = "", stack1;
  buffer += "\n						maxlength=\"";
  stack1 = depth0.maximumLength;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "this.maximumLength", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\"\n					";
  return buffer;}

function program7(depth0,data) {
  
  var buffer = "", stack1;
  buffer += "\n						minlength=\"";
  stack1 = depth0.minimumLength;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "this.minimumLength", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\"\n					";
  return buffer;}

function program9(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n						";
  foundHelper = helpers.showTyping;
  stack1 = foundHelper || depth0.showTyping;
  stack2 = helpers['if'];
  tmp1 = self.program(10, program10, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n					";
  return buffer;}
function program10(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n							<a href=\"javascript:void(0)\" class=\"yodlee-font-icon svg_pass-close eyeIcon\" aria-label=\"";
  stack1 = "unmasked_text";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\" role=\"button\"></a>\n						";
  return buffer;}

  buffer += "<form>\n	<div class=\"loginForm\">\n		";
  foundHelper = helpers.fieldInfo;
  stack1 = foundHelper || depth0.fieldInfo;
  stack1 = (stack1 === null || stack1 === undefined || stack1 === false ? stack1 : stack1.questionAndAnswerValues);
  stack2 = helpers.each;
  tmp1 = self.program(1, program1, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n		<div class=\"row timerRow collapse\">\n			<div class = \"small-12 medium-portrait-4 medium-4 medium-min-single-col medium-portrait-offset-4 medium-offset-4 column\">\n				<span class = \"timmer-cls\">";
  foundHelper = helpers.timeOutTime;
  stack1 = foundHelper || depth0.timeOutTime;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "timeOutTime", { hash: {} }); }
  buffer += escapeExpression(stack1) + " ";
  stack1 = "seconds_left";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</span></div>\n					<span aria-live=\"polite\" class=\"ada-offscreen\" id=\"timerSecLeft\">";
  foundHelper = helpers.timeOutTime;
  stack1 = foundHelper || depth0.timeOutTime;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "timeOutTime", { hash: {} }); }
  buffer += escapeExpression(stack1) + " ";
  stack1 = "seconds_left";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</span>\n			\n		</div>\n		<div class=\"row collapse\">\n			<div class = \"small-12 medium-portrait-7 medium-7 medium-min-single-col large-7 medium-portrait-offset-4 medium-offset-4 column\">\n				<input class=\"primary button disabled expand\" type=\"submit\" value=\"";
  stack1 = "next_btn_label";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\" aria-disabled=\"true\" />\n			</div>\n		</div>\n	</div>\n</form>";
  return buffer;});
templates['siteRefreshStatus'] = template(function (Handlebars,depth0,helpers,partials,data) {
  helpers = helpers || Handlebars.helpers;
  var buffer = "", stack1, foundHelper, self=this, functionType="function", helperMissing=helpers.helperMissing, undef=void 0, escapeExpression=this.escapeExpression;


  buffer += "<div class=\"row\" id=\"refreshStatus\">\n	<div class=\"small-12 medium-12 medium-min-single-col large-12 small-centered columns\">\n		<div class=\"row collapse status-width\">\n			<div class=\"small-12 medium-2 medium-min-single-col medium-push-10 large-2 large-push-10 column\">\n				<div class=\"loading\"></div>\n			</div>\n			<div class=\"small-12 medium-10 medium-min-single-col medium-pull-2 large-10 large-pull-2 column end\">\n				<div class=\"statusMessage inline\">";
  foundHelper = helpers.message;
  stack1 = foundHelper || depth0.message;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "message", { hash: {} }); }
  buffer += escapeExpression(stack1) + "</div>\n			</div>\n		</div>\n	</div>\n</div>";
  return buffer;});
return templates;
});
define('10003593_js/models/header',[], function() {
    var Header = Backbone.Model.extend({
        defaults : {
            displayName : '',
            baseUrl : '',
            loginUrl : '',
            siteId : 0
        },

        initialize : function(options)  {
        	console.log(options);
        }
    });
    return Header;
});
define('10003593_js/views/headerView',['10003593_js/compiled/finappCompiled'], function(templates) {
	var Header = Marionette.ItemView.extend({

		template: templates['header'],

		events : {
			'click .popwin' : 'openNewWindow'
		},

		onShow : function() {
			var self = this;
			this.$el.find('#siteLogoDiv img').on('load', function() { self.showHideSiteName() });
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
define('10003593_js/views/siteRefreshStatusView',[
        '10003593_js/compiled/finappCompiled',
        '10003593_js/common/dataParser'
        ], function( templates, DataParser) {
    var SiteRefreshStatusView = Backbone.Marionette.ItemView.extend({
        initialize: function (options) {
            this.siteInfo = options.siteInfo;
            this.flowType = options.flowType;
            this.isMFARequestCompleted = false;
            this.moduleKey = options.moduleKey;
            this.listenTo(this.model, 'change:message', this.updateStatusMessage);
            this.STOP_REFRESH_REASON_USER_ABORTED = 101;
            this.STOP_REFRESH_REASON_MFA_TIMEDOUT = 102;
            this.MFA_INFO_NOT_PROVIDED_IN_REAL_TIME_BY_USER_VIA_APP = 522;
        },

        updateStatusMessage : function() {
           this.render();
        },

        template: templates['siteRefreshStatus'],

        triggerSiteRefresh : function( ) {

            this.stopSiteRefresh( null, true );
        },

        refreshAccountAtSiteLevel : function() {
            var self = this;
            var result = DataParser.getStartSiteRefreshInputData(this.siteAccountId, this.model.get('siteRefreshMode'));
            var apiInfo = Application.Wrapper.getAPIDetails(result); 
            this.model.fetch({
                type: apiInfo.method,
                url : apiInfo.url,
                data: apiInfo.data,
                success : function(model, response) {
                    self.checkSiteRefreshStatus();
                },
                error: function(model, error) {
                    Logger.error(error);
                }
            });
        },

        stopSiteRefresh : function( reason, forceRefresh ) {
            var reasonId = ( reason == 'TIMED_OUT' ) ? this.STOP_REFRESH_REASON_MFA_TIMEDOUT : this.STOP_REFRESH_REASON_USER_ABORTED;
            var inputData = DataParser.getStopSiteRefreshInputData( this.siteAccountId, reasonId );
            var self = this;
            var apiInfo = Application.Wrapper.getAPIDetails( inputData ); 

            this.model.save(null, {
                type: apiInfo.method,
                url : apiInfo.url,
                data: apiInfo.data,
                success : function(model, response) {
                    if( reason == 'TIMED_OUT' ) {
                        var data = { siteAccountId : self.siteAccountId , siteInfo : self.siteInfo, flowType : self.flowType };
                        data.errorCode = self.MFA_INFO_NOT_PROVIDED_IN_REAL_TIME_BY_USER_VIA_APP;                        
                        Application.AppRouter.route(self.moduleKey, 'loadAccountStatusModule', true, data);
                    } else if( forceRefresh ) {
                        self.pollSiteRefresh( forceRefresh );
                    }
                },
                error: function(model, error) {
                    Logger.error(error);
                }
            });

        },

        checkSiteRefreshStatus : function() {
            var self = this;
            var status =  this.model.get('siteRefreshStatusId');
            if( !this.siteRefreshMode ) {
                this.siteRefreshMode = this.model.get('siteRefreshMode');
            }
            if( status == '1' || status == '2' ) {
                if( this.siteRefreshMode.refreshModeId == '1' && !this.isMFARequestCompleted ) {
                    Logger.debug('Required Mfa...');
                    this.model.set({message : Utilities.getString('Retrieving_mfa_info_msg')});
                    Application.AppRouter.route(this.moduleKey, 'showMFASecurityView', false, {'siteAccountId': this.model.get('siteAccountId'), flowType : self.flowType });
                } else {
                    if( status == '2' ) {
                        this.model.set({message : Utilities.getString('login_success_message')});
                    }
                    setTimeout(function() { 
                            self.pollSiteRefresh();
                        }, 5000);                    
                    }
            } else {
                var data = { siteAccountId : this.siteAccountId , siteInfo : this.siteInfo, flowType : self.flowType };
                data.errorCode = this.model.get('errorCode');
                if( status == 3 && this.model.get('errorCode') == '402' ) {
                    Application.AppRouter.route(this.moduleKey, 'loadSiteLoginFormModule', true, data);
                } else {
				    Application.AppRouter.route(this.moduleKey, 'loadAccountStatusModule', true, data);
                }
			}
        },

        pollSiteRefresh : function( forceRefresh ) {
            var self = this;
            var result = DataParser.getSiteRefreshInfoInputData(this.siteAccountId);
            var apiInfo = Application.Wrapper.getAPIDetails(result); 
            self.model.fetch({
                type: apiInfo.method,
                url : apiInfo.url,
                data: apiInfo.data,
                success : function(model, response) {
                    if( forceRefresh ) {
                        self.refreshAccountAtSiteLevel();
                    } else {
                        self.checkSiteRefreshStatus();
                    }
                },
                error: function(model, error) {
                    Logger.error(error);
                }
            });
        }
    });

    return SiteRefreshStatusView;
});
define('10003593_js/views/baseLayoutView',[
    '10003593_js/compiled/finappCompiled',
    '10003593_js/models/header',
    '10003593_js/models/siteRefreshStatus',
    '10003593_js/views/headerView',
    '10003593_js/views/siteRefreshStatusView'
    ], 
    function(
        templates, 
        HeaderModel,
        SiteRefreshStatus, 
        HeaderView,
        SiteRefreshStatusView ) {
        var BaseLayoutView = Backbone.Marionette.LayoutView.extend({

            className: 'site-form',

            initialize: function (options) {
                this.siteInfo = options.data.siteInfo;
                this.headerModel = new HeaderModel(options.data.siteInfo);
                this.flowType = options.data.flowType;
                this.templateHelpers.flowType = options.data.flowType;
                this.siteRefreshStatus = new SiteRefreshStatus({ message : Utilities.getString('refresh_intiated_message') });
                this.moduleKey = options.moduleKey;
            },

            template: templates['baseLayout'],
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
            regions: {
              header: "#header",
              content: "#content",
              status: '#status'
            },

            ui: {
                tooltip: '.i-tick'
            },

            events: {
                'click @ui.tooltip': 'showTooltip'
            },

            onShow : function() {
                var headerView = new HeaderView({ model : this.headerModel });
                console.log(this.headerModel);
                this.header.show(headerView);
                this.siteRefreshStatusView = new SiteRefreshStatusView({ model : this.siteRefreshStatus, moduleKey : this.moduleKey, flowType : this.flowType })
                this.siteRefreshStatusView.siteInfo = this.siteInfo;
                this.status.show(this.siteRefreshStatusView);
            },

            showSiteRefreshStatus : function(options) {
                if( options && options.message ) {
                    this.siteRefreshStatus.set('message', options.message);
                }
                this.status.$el.show();
            },

            hideSiteRefreshStatus : function() {
                this.status.$el.hide();     
            }

        });
        return BaseLayoutView;
});
define('10003593_js/views/MFASecurityFormView',['10003593_js/views/baseLayoutView','10003593_js/common/dataParser'], function( BaseLayoutView, DataParser ) {

    var MFASecurityFormView = Backbone.Marionette.LayoutView.extend({

        initialize: function (options) {
           this.moduleKey = options.moduleKey;
           this.stop = false;
           this.flowType = options.flowType;                
           this.templateHelpers.flowType = options.flowType;
           this.startCount = 0;
        },

        events: {
            'keyup input[type!="submit"]' : 'enableSubmitButton',
            'submit': 'putMFAResponseForSite',
            'paste input[type!="sumbit"]' : 'enableButton',    
            'click .eyeIcon' : 'showHidePassword'
        },

        enableButton : function() {
            var self = this;
            setTimeout(function() {
                self.enableSubmitButton();
            }, 4);
        },  
        templateHelpers : {
            showTyping : function() {
                if( Utilities.getParam('show_type_enabled') == 'true' || Utilities.getParam('show_type_enabled') === true ) {
                    if( this.flowType != 'edit' && this.flowType != 'refresh' ) {
                        return true;
                    }
                }
                return false;
             } 
        },      
        setTimmer: function(secondsleft) {
            if(secondsleft>0){
                if(this.startCount > 2 || secondsleft < 10  ){
                    this.$el.find("#timerSecLeft").attr('aria-hidden','true');
                    this.startCount++;
                } else if(secondsleft == 10){
                    this.$el.find('#timerSecLeft').removeAttr('aria-hidden');
                    this.$el.find('#timerSecLeft').html('');
                    this.$el.find('#timerSecLeft').html(secondsleft +  Utilities.getString('seconds_left'));
                }
            }
            this.timmerContainer.text(secondsleft +" " + Utilities.getString('seconds_left') );
        },

        getTime: function() {
            splittime = this.timmerContainer.text().split(" ");
            return parseInt(splittime[0]);
        },

        timmer: function() {
            var time = this.getTime() - 1;
            this.setTimmer(time);
            return time;
        },

        startTimer: function() {
            var self = this;
            (function loop(){
                if( !self.stop ) {
                    self.timmerId = setTimeout(function(){
                        var time = self.timmer();
                        if(time) {
                            loop();
                        } else {
                            Application.AppRouter.route(self.moduleKey, 'checkSiteRefreshStatus', false, {'refreshAction': 'stopRefresh', 'reason' : 'TIMED_OUT'});
                            window.clearTimeout(self.timmerId);
                        }
                    }, 1000);
                }
            })();
        },

        stopTimer : function() {
            this.stop = true;
        },

        onShow: function() {
            this.timmerContainer = this.$el.find('.timmer-cls');
            this.startTimer();
            this.enableSubmitButton();
        },

        enableSubmitButton : function() {
            var enabledButton = this.validateFormFields();
            if(enabledButton) {
                $(".site-form .button").removeClass("disabled");
                $(".site-form .button").prop("disabled","");
            } else {
                $(".site-form .button").addClass("disabled");
                $(".site-form .button").prop("disabled","disabled");
            }
        },

        getFormInputMap : function() {
            var formFieldMap = {};
            var formFields = this.$el.find('.formField');
            $.each(formFields, function(key, val) {
                console.log(val);
                formFieldMap[$(val).attr('name')] = $(val).val();
            });
            return formFieldMap;
        },

        putMFAResponseForSite : function( e ) {
            e.preventDefault();
            if( this.validateFormFields() ) {
                this.stopTimer();
                var inputData = this.getParsedMfaInputData();
                var self = this;
                var apiInfo = Application.Wrapper.getAPIDetails( inputData ); 
                Application.AppRouter.route(this.moduleKey, 'showSiteRefreshStatus', false, {'siteAccountId': this.model.get('siteAccountId')});
                this.$el.hide();

                this.model.save(null, {
                    type: apiInfo.method,
                    url : apiInfo.url,
                    data: apiInfo.data,
                    success : function(model, response) {
                        console.log(response);
                        console.log(self.moduleKey);
                        if( response.primitiveObj ) {
                            setTimeout( function() {
                            Application.AppRouter.route(self.moduleKey, 'showMFASecurityView', false, {'siteAccountId': self.model.previous('siteAccountId'), flowType : self.flowType });
                            }, 2000);
                        } else {
                            Application.AppRouter.route(self.moduleKey, 'checkSiteRefreshStatus', false, {'refreshAction': 'polling', flowType : self.flowType });
                        }
                    },
                    error: function(model, error) {
                        console.log(error);
                    }
                });
            }
            return false;
        },

        validateFormFields : function() {
            var enabledButton = true;

            var formFields = this.$el.find('.formField');
            $.each(formFields, function(key, val) {
                Logger.debug('Field '+$(val).attr('type'))
                if( $(val).hasClass('star_field') ) {
                    var value = $(val).val();
                    if( $(val).attr('type') == 'CHECKBOX'.toLowerCase()) {
                        if(!$(val).is(':checked')) {
                            enabledButton = false;
                        }
                    } else if( $.trim(value).length == 0 ) {
                        enabledButton = false;
                    }
                }
            });

            if(enabledButton) {
                $(".site-form .button").removeClass("disabled");
                $(".site-form .button").removeAttr('aria-disabled');
            } else {
                $(".site-form .button").addClass("disabled");
                $(".site-form .button").attr('aria-disabled','true');
            }
            return enabledButton;
        },

        showHidePassword : function(event){
            var inputField = this.$el.find("input.formField");
            if(Utilities.toggleInputTypes(inputField)){
                $(".eyeIcon").removeClass("open");
                $(".eyeIcon").removeClass("svg_pass-open");
                $(".eyeIcon").addClass("svg_pass-close");
                $(".eyeIcon").attr('aria-label', Utilities.getString('masked_text'));
            }else{
                $(".eyeIcon").addClass("open");
                $(".eyeIcon").removeClass("svg_pass-close");
                $(".eyeIcon").addClass("svg_pass-open");
                $(".eyeIcon").attr('aria-label', Utilities.getString('unmasked_text'));
            }
        }

    });

    return MFASecurityFormView;
});

define('10003593_js/views/securityKeyView',[
	'10003593_js/compiled/finappCompiled', 
	'10003593_js/views/MFASecurityFormView',
	'10003593_js/common/dataParser'], function(templates, MFASecurityFormView, DataParser) {

    var SecurityKeyView = MFASecurityFormView.extend({

        template: templates['securityKey'],

	    getParsedMfaInputData : function() {
			var formFieldMap = this.getFormInputMap();
			var result = DataParser.getMFATokenPostData(this.model.get('fieldInfo'), formFieldMap, this.model.get('siteAccountId'));
			return result;
	    }

    });
    return SecurityKeyView;
});
define('10003593_js/views/capchaView',['10003593_js/compiled/finappCompiled','10003593_js/views/MFASecurityFormView','10003593_js/common/dataParser'], 
	function(templates, MFASecurityFormView, DataParser) {

    var CapchaView = MFASecurityFormView.extend({

        template: templates['capcha'],

		getParsedMfaInputData : function(e) {
			var formFieldMap = this.getFormInputMap();
			var result = DataParser.getMFACaptchaTokenPostData(this.model.get('fieldInfo'), formFieldMap, this.model.get('siteAccountId'));
			return result;
        }        

    });

    return CapchaView;
});
define('10003593_js/views/securityQuestionsView',['10003593_js/compiled/finappCompiled', 
	'10003593_js/views/MFASecurityFormView',
	'10003593_js/common/dataParser'], 
	function(templates, MFASecurityFormView, DataParser) {

    var SecurityQuestionView = MFASecurityFormView.extend({

        template: templates['securityQuestions'],

        getParsedMfaInputData : function(e) {
			var formFieldMap = this.getFormInputMap();
			var result = DataParser.getMFASecurityQuestionPostData(this.model.get('fieldInfo'), formFieldMap, this.model.get('siteAccountId'));
			return result;
        }

    });
    
    return SecurityQuestionView;
});
define('10003593_js/views/errorView',[
    '10003593_js/compiled/finappCompiled'
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
define('10003593_js/controller/siteRefreshController',[
	'10003593_js/models/siteAccount',
	'10003593_js/models/siteRefreshStatus',
	'10003593_js/models/MFASecurity',
	'10003593_js/models/errorModel',
	'10003593_js/views/baseLayoutView',
	'10003593_js/views/securityKeyView',
	'10003593_js/views/capchaView',
	'10003593_js/views/securityQuestionsView',
	'10003593_js/views/siteRefreshStatusView',
	'10003593_js/common/dataParser',
	'10003593_js/views/errorView'
	],
	function(
		SiteAccount,
		SiteRefreshStatus,
		MFASecurity,
		ErrorModel,		
		BaseLayoutView,
	 	SecurityKeyView,
	 	CapchaView,
		SecurityQuestionsView,
		SiteRefreshStatusView,
		DataParser,
		ErrorView) {
		var SiteRefreshController = Backbone.Marionette.Controller.extend({
			initialize: function(options) {
				console.log('Site Refresh Controller is initialized.');
	  		},

			start: function(options) {
				if( !options.data ) {
					options.data = {};
				}

				this.siteInfo = options.data.siteInfo;
				this.region = options.region;
				this.flowType = options.data.flowType;



				if( this.siteInfo ) {
					this.siteAccountId = options.data.siteAccountId;
					this.renderBaseLayout(options);
					this.checkSiteRefreshStatus( options.data );
				} else {
					if(!this.flowType){
	                    Logger.error('Site Refresh Controller : Flow Type is not found.');
	                    var errormodel = new ErrorModel({ errorDescription : Utilities.getString('error_flowtype_not_found') });
	                    self.errorView = new ErrorView({
	                    	moduleKey : self.moduleKey, 
							model : errormodel
	                    });
						options.region.show(this.errorView);
						return;
					} 
					yo.inlineSpinner.show( this.region.el );
					this.siteAccountId = options.params.siteAccountId;
					this.validateMemSiteAccount( options );
				}
			},
			renderBaseLayout : function(options){
				this.baseLayoutView = new BaseLayoutView(options);
				options.region.show(this.baseLayoutView);
			},

			validateMemSiteAccount : function( options ){
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
							self.siteRefreshInfo = model.get('siteRefreshInfo');
							options.data.siteInfo = self.siteInfo;
							options.data.siteAccountId = self.siteAccountId;
							self.checkSuggesteFlow( options );

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
			checkSuggesteFlow : function( options ){
				var self = this;
				var result = DataParser.getStartSiteRefreshInputData(this.siteAccountId, this.siteRefreshInfo.siteRefreshMode);
	        	var apiInfo = Application.Wrapper.getAPIDetails(result); 
	        	this.siteRefreshStatus = new SiteRefreshStatus({moduleKey : this.moduleKey});
	        	this.siteRefreshStatus.fetch({
	                type: apiInfo.method,
	                url : apiInfo.url,
	                data: apiInfo.data,
	                context : this,
	                success : function(model, response) {
	                	var suggestedFlowId = model.get('suggestedFlow').suggestedFlowId;
						if( suggestedFlowId == 1){ //TODO : Refresh is not eligible
							var errorDescription;
							if(model.get('suggestedFlowReason').suggestedFlowReasonId == 4){ //TODO : Update in progress
								errorDescription = Utilities.getString('error_account_in_progress');
							} else if(model.get('suggestedFlowReason').suggestedFlowReasonId == 5){ //TODO : Recently refreshed
								errorDescription = Utilities.getString('error_account_already_refreshed');
							} else {
								errorDescription = Utilities.getString('generic_error_description');
							}
							Logger.debug('MFA refresh: Suggested Flow is 1, Refresh is not eligible.');
	                    	var errormodel = new ErrorModel({ errorDescription : errorDescription });
		                    self.errorView = new ErrorView({
		                    	moduleKey : self.moduleKey, 
								model : errormodel
		                    });
		                    self.region.show(self.errorView);
						} else if(suggestedFlowId == 2){ //TODO : Contnue check site refresh
							self.renderBaseLayout(options);
							options.data.siteRefreshInfo = response;
							self.checkSiteRefreshStatus(options.data);
						} else if(suggestedFlowId == 3){ //TODO : Re-direct to edit site credential page
							Logger.debug('DEBUG : Navigating to edit credentails, since suggested flow is edit');
							Application.AppRouter.route(self.moduleKey, 'loadSiteLoginFormModule', true, {'siteAccountId': self.siteAccountId, siteInfo : self.siteInfo, flowType : 'edit' });
						} else if(suggestedFlowId == 4){
							//FIXME :Re-authorization required! Implementation not available
						}
					},
	                error: function(model, error) {
						Logger.error('MFA refresh: API is failing, to fetch the suggested flow.');
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

			},
			checkSiteRefreshStatus : function(options) {
				if( options.refreshAction == 'polling' ) {
					this.baseLayoutView.siteRefreshStatusView.model.set({ message : Utilities.getString('verifying_security_message')});
					this.baseLayoutView.siteRefreshStatusView.isMFARequestCompleted = true;
					this.baseLayoutView.siteRefreshStatusView.pollSiteRefresh();		
				} else if( options.refreshAction == 'stopRefresh' ) {
					this.baseLayoutView.siteRefreshStatusView.stopSiteRefresh(options.reason);
				} else {
					this.siteAccountId = options.siteAccountId;
					this.baseLayoutView.siteRefreshStatusView.siteAccountId = this.siteAccountId;
					if( options.refreshAction == 'forceRefresh' ) {
						this.baseLayoutView.siteRefreshStatusView.triggerSiteRefresh(options);
					} else {
						this.baseLayoutView.siteRefreshStatusView.model.set(DataParser.parseSiteRefreshStatus(options.siteRefreshInfo));
						this.baseLayoutView.siteRefreshStatusView.checkSiteRefreshStatus(options);
					}
				}
			},

			showSiteRefreshStatus : function() {
				this.baseLayoutView.showSiteRefreshStatus();
			},

			showMFASecurityView : function() {
				var self = this;
            	var result = DataParser.getMFAResponseForSite(this.siteAccountId);
            	var apiInfo = Application.Wrapper.getAPIDetails(result); 
            	var mfaSecurity = new MFASecurity();
	            mfaSecurity.fetch({
	                type: apiInfo.method,
	                url : apiInfo.url,
	                data: apiInfo.data,
	                success : function() {
	                    if( mfaSecurity.get('errorCode') >= 0 ) {
	                    	self.checkSiteRefreshStatus({ refreshAction : 'polling' });
	                    } else if( mfaSecurity.get('isMessageAvailable') && !mfaSecurity.get('retry') ) {
		                    var mfaSecurityView = null;
		                    if( mfaSecurity.get('mfaType') == 'SECURITY_QUESTION' ) {
		                    	mfaSecurityView = new SecurityQuestionsView({model : mfaSecurity, moduleKey : self.moduleKey});
		                    } else if(mfaSecurity.get('mfaType') == 'IMAGE') {
		                    	var apiInfo = Application.Wrapper.getAPIDetails('/services/image/captcha/'+mfaSecurity.get('imageId')+'/')
		                    	mfaSecurity.set('captchaImageUrl', apiInfo.url);
		                    	mfaSecurityView = new CapchaView({model : mfaSecurity, moduleKey : self.moduleKey, flowType : self.flowType});
		                    } else if(mfaSecurity.get('mfaType') == 'TOKEN_ID') {
		                    	mfaSecurityView =  new SecurityKeyView({model : mfaSecurity, moduleKey : self.moduleKey, flowType : self.flowType});
		                    } else {
		                    	alert('error');
		                    }
		                    self.baseLayoutView.hideSiteRefreshStatus();
		                    self.baseLayoutView.content.show(mfaSecurityView);
		            	} else if( mfaSecurity.get('retry') ) {
		            		setTimeout(function() {
		            			self.showMFASecurityView();
		            		}, 5000)
		            	} else {
		            		self.checkSiteRefreshStatus({ refreshAction : 'polling' });
		            	}
	                },
	                error: function(model, error) {
	                    Logger.error('Error while fetching mfaresponse : '+error.responseText);
	                }
	            });
       		}
		});
	return SiteRefreshController;
});
define('10003593_js/finapp',['10003593_js/controller/siteRefreshController'], function(SiteRefreshController) {
	var module = Application.Appcore.Module.extend({
		controller : SiteRefreshController,

		initialize : function(options) {
			Logger.debug('Site Refresh Controller is intialized.');
		}

	});
	return module;
});

