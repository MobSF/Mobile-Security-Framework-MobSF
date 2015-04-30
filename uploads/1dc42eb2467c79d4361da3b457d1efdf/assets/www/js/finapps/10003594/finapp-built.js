define('10003594_js/finappConfig',[],function(){ return ({
	dependsJs : ['/js/accountParseHandler.js']
}) });
define('10003594_js/common/dataParser',[], function() {
    
	var DataParser = function(){

		var ACCOUNTS_FOR_SITE = "siteAccountByMemSiteAccId";
		var SITE_REFRESH_INFO_API = 'siteRefreshInfo';

		var _parseItemSummary = function( item, itemAccount ) {
			var result;
			//Logger.debug(response);
			var additionalInfo = false;
			if( itemAccount || item.isItemRefreshInProgress ) {
				result = {};
				if( itemAccount ) {
					result.accountNumber = itemAccount.accountNumber;
					if( itemAccount.accountType != 'unknown' ) {
						result.accountType = itemAccount.accountType;
					}
					result.balance = itemAccount.accountValue;
					result.displayName = itemAccount.accountDisplayName;
				}
				if( !result.displayName ) {
					result.displayName = item.itemDisplayName;
				}

				result.container = item.containerName;			
				result.refreshInProgress = item.isItemRefreshInProgress
				result.errorCode = item.errorCode;
				result.lastUpdatedTime = item.lastUpdatedTime;
			} 
			return result;
		};

		var _parseSiteRefreshStatus = function( response ) {
			var result = {};
			result.siteRefreshStatusId = response.siteRefreshStatus.siteRefreshStatusId;
			result.errorCode = response.code;
			if( response.siteAccountId ) {
				result.siteAccountId = response.siteAccountId;
			}
			//console.log(result);
			return result;
		};

		var _parseSiteAccount = function ( response ) {
			var result = {};
			result.siteRefreshStatus = _parseSiteRefreshStatus( response[0].siteRefreshInfo );
			if( response[0].itemSummary ) {
				var items = AccountParseHandler.parseAccountsByFilter(response[0].itemSummary);
				if( items && items.length > 0 ) {
					result.itemSummaries = [];
					var k = 0;
					for( var i in items ) {
						if( items[i].accounts && items[i].accounts.length > 0 ) {
							for( var j in items[i].accounts ) {
								var val = _parseItemSummary(items[i], items[i].accounts[j]);
								if( val ) {
									result.itemSummaries[k++] = val;
								}
							}
						} else {
							var val = _parseItemSummary(items[i]);
							if( val ) {
								result.itemSummaries[k++] = _parseItemSummary(items[i]);
							}
						}
					}
				}
			}
			result.isAgentError = response[0].isAgentError;
			result.isSiteError = response[0].isUARError;
			result.isUARError = response[0].isUARError;
			return result;
		}

		var _getSiteRefreshInfoInputData = function(siteAccountId)	{
			var result = {};
			result.method = 'POST';
			result.data = {'memSiteAccId' : ''+siteAccountId+'' };
			result.apiUrl = SITE_REFRESH_INFO_API;
			return result;			
		}


		var _getSiteAccountsInputData = function(siteAccountId) {
			var result = {};
			result.method = 'POST';
			result.data = {'siteAccountFilter.memSiteAccIds[0]' : ''+siteAccountId+'',
				'siteAccountFilter.itemSummaryRequired' : '2' };
			result.apiUrl = ACCOUNTS_FOR_SITE;
			return result;	
		};		

		return {
	        parseSiteAccount : _parseSiteAccount,
	        parseItemSummary : _parseItemSummary,
	        parseSiteRefreshStatus : _parseSiteRefreshStatus,
	        getSiteRefreshInfoInputData : _getSiteRefreshInfoInputData,
	        getSiteAccountsInputData : _getSiteAccountsInputData
	    }
	}
	return new DataParser();
});

define('10003594_js/models/siteAccount',['10003594_js/common/dataParser'], function(DataParser) {
	var SiteAccount = Backbone.Model.extend({

		parse : function(response) {
			return DataParser.parseSiteAccount(response);
		}
	});
  return SiteAccount;
});
define('10003594_js/models/itemSummary',['10003594_js/common/dataParser'], function(DataParser) {
    var ItemSummary = Backbone.Model.extend({
        defaults: {
            accountName : null,
            accountType : null,
            container : null,
            balance : null,
            accountNumber : null,
            displayName : null
        },

        parse : function(response) {
        	return DataParser.parseItemSummary(response);
        }
  });
  return ItemSummary;
});
define('10003594_js/collections/itemSummaries',['10003594_js/models/itemSummary', '10003594_js/common/dataParser'], function(ItemSummary, DataParser) {
	var ItemSummries = Backbone.Collection.extend({
		model: ItemSummary,

		initialize : function() {

		},

		parse : function(response) {
			return DataParser.parseSiteAccounts(response);
		}
	});
  return ItemSummries;
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

define('10003594_js/compiled/finappCompiled',['handlebars'], function(Handlebars) {
  var template = Handlebars.template, templates = Handlebars.templates = Handlebars.templates || {};
templates['baseLayout'] = template(function (Handlebars,depth0,helpers,partials,data) {
  helpers = helpers || Handlebars.helpers;
  var foundHelper, self=this;


  return "<div>\n	<div id=\"header\"></div>\n	<div id=\"content\"></div>\n</div>";});
templates['errorPage'] = template(function (Handlebars,depth0,helpers,partials,data) {
  helpers = helpers || Handlebars.helpers;
  var buffer = "", stack1, stack2, foundHelper, tmp1, self=this, functionType="function", helperMissing=helpers.helperMissing, undef=void 0, escapeExpression=this.escapeExpression;

function program1(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n		<div class=\"row\">\n			<div class=\"column small-12 medium-portrait-6 medium-min-12 medium-6\">\n				<input type=\"button\" value=\"";
  foundHelper = helpers.leftButtonText;
  stack1 = foundHelper || depth0.leftButtonText;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "leftButtonText", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" class=\"tertiary actionButton expand button\" id=\"";
  foundHelper = helpers.leftButton;
  stack1 = foundHelper || depth0.leftButton;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "leftButton", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" />\n			</div>\n			";
  foundHelper = helpers.rightButton;
  stack1 = foundHelper || depth0.rightButton;
  stack2 = helpers['if'];
  tmp1 = self.program(2, program2, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n		</div>\n	";
  return buffer;}
function program2(depth0,data) {
  
  var buffer = "", stack1;
  buffer += "\n				<div class=\"column small-12 medium-portrait-6 medium-6 medium-min-12 \">\n					<input type=\"button\" value=\"";
  foundHelper = helpers.rightButtonText;
  stack1 = foundHelper || depth0.rightButtonText;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "rightButtonText", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" class=\"tertiary actionButton expand button\" id=\"";
  foundHelper = helpers.rightButton;
  stack1 = foundHelper || depth0.rightButton;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "rightButton", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" />\n				</div>\n			";
  return buffer;}

  buffer += "<div class=\"row errorSection\">\n	<div class = \"small-12 medium-12 large-12 error-title\">";
  foundHelper = helpers.errorTitle;
  stack1 = foundHelper || depth0.errorTitle;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "errorTitle", { hash: {} }); }
  buffer += escapeExpression(stack1) + "</div>\n	<div class=\"small-12 medium-12 large-12 error-description\">\n		";
  foundHelper = helpers.errorDescription;
  stack1 = foundHelper || depth0.errorDescription;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "errorDescription", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\n	</div>\n	";
  foundHelper = helpers.actionButtons;
  stack1 = foundHelper || depth0.actionButtons;
  stack2 = helpers['if'];
  tmp1 = self.program(1, program1, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n</div>";
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

  buffer += "<div class=\"row collapse\">\n	<div class=\"small-12 medium-portrait-4 medium-4 medium-min-single-col column siteLogo\">\n		";
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
  buffer += "\n		<div id=\"siteLogoDisplayName\" class=\"siteDisplayName\" role=\"heading\"  aria-level=\"2\">";
  foundHelper = helpers.displayName;
  stack1 = foundHelper || depth0.displayName;
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</div>				\n	</div>\n	<div class=\"small-12 medium-portrait-8 medium-8 medium-min-single-col column hide-for-small-only show-for-medium-portrait\">\n		<div class=\"siteUrl\">\n			";
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
  buffer += "\n		</div>\n	</div>\n</div>";
  return buffer;});
templates['itemSummary'] = template(function (Handlebars,depth0,helpers,partials,data) {
  helpers = helpers || Handlebars.helpers;
  var buffer = "", stack1, stack2, stack3, foundHelper, tmp1, self=this, functionType="function", helperMissing=helpers.helperMissing, undef=void 0, escapeExpression=this.escapeExpression;

function program1(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n					- ";
  foundHelper = helpers.accountNumber;
  stack1 = foundHelper || depth0.accountNumber;
  foundHelper = helpers.maskAccountNumber;
  stack2 = foundHelper || depth0.maskAccountNumber;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "maskAccountNumber", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\n					";
  return buffer;}

function program3(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n					<div class=\"ada-offscreen\" >";
  stack1 = "account_status";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + " ";
  stack1 = "status_inprogress";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</div>			\n				";
  return buffer;}

function program5(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n					";
  foundHelper = helpers.errorCode;
  stack1 = foundHelper || depth0.errorCode;
  stack2 = helpers['if'];
  tmp1 = self.program(6, program6, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.program(8, program8, data);
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n				";
  return buffer;}
function program6(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n							<div class=\"ada-offscreen\">";
  stack1 = "account_status";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + " ";
  stack1 = "status_error";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</div>\n					";
  return buffer;}

function program8(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n						<div class=\"ada-offscreen\">";
  stack1 = "account_status";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + " ";
  foundHelper = helpers.getStatus;
  stack1 = foundHelper || depth0.getStatus;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "getStatus", { hash: {} }); }
  buffer += escapeExpression(stack1) + "</div>\n					";
  return buffer;}

function program10(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n			<i class=\"refresh\"></i>\n			<div class=\"message\" >";
  stack1 = "status_inprogress";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</div>			\n		";
  return buffer;}

function program12(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n			<i class=\"yodlee-font-icon svg_settings settings\" aria-label=\"Account settings\" role=\"button\" tabindex=\"0\"></i>\n			";
  foundHelper = helpers.errorCode;
  stack1 = foundHelper || depth0.errorCode;
  stack2 = helpers['if'];
  tmp1 = self.program(13, program13, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.program(15, program15, data);
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n		";
  return buffer;}
function program13(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n				<div class=\"message error\">";
  stack1 = "status_error";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</div>\n			";
  return buffer;}

function program15(depth0,data) {
  
  var buffer = "", stack1;
  buffer += "\n				<div class=\"message\" aria-hidden=\"true\">";
  foundHelper = helpers.getStatus;
  stack1 = foundHelper || depth0.getStatus;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "getStatus", { hash: {} }); }
  buffer += escapeExpression(stack1) + "</div>\n			";
  return buffer;}

  buffer += "<div class=\"list-item row collapse\">\n	<div class=\"small-9 medium-portrait-9 medium-9 large-10 column\">\n		<div class=\"row collapse\">\n			<div class=\"small-12 medium-portrait-8 medium-8 medium-min-single-col large-9 column\">\n				<div class=\"title\">";
  foundHelper = helpers.displayName;
  stack1 = foundHelper || depth0.displayName;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "displayName", { hash: {} }); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n					";
  foundHelper = helpers.accountNumber;
  stack1 = foundHelper || depth0.accountNumber;
  stack2 = helpers['if'];
  tmp1 = self.program(1, program1, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n				</div>\n				<div class=\"accountType\">";
  foundHelper = helpers.accountType;
  stack1 = foundHelper || depth0.accountType;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "accountType", { hash: {} }); }
  buffer += escapeExpression(stack1) + "</div>\n				";
  foundHelper = helpers.refreshInProgress;
  stack1 = foundHelper || depth0.refreshInProgress;
  stack2 = helpers['if'];
  tmp1 = self.program(3, program3, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.program(5, program5, data);
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n			\n			</div>\n			<div class=\"small-12 medium-portrait-4 medium-4 medium-min-single-col large-3 column end\">\n				";
  foundHelper = helpers.balance;
  stack1 = foundHelper || depth0.balance;
  stack2 = {};
  foundHelper = helpers.container;
  stack3 = foundHelper || depth0.container;
  stack2['container'] = stack3;
  foundHelper = helpers.currencyFormat;
  stack3 = foundHelper || depth0.currencyFormat;
  tmp1 = {};
  tmp1.hash = stack2;
  if(typeof stack3 === functionType) { stack1 = stack3.call(depth0, stack1, tmp1); }
  else if(stack3=== undef) { stack1 = helperMissing.call(depth0, "currencyFormat", stack1, tmp1); }
  else { stack1 = stack3; }
  buffer += escapeExpression(stack1) + " ";
  foundHelper = helpers.getFormattedLastupdatedTime;
  stack1 = foundHelper || depth0.getFormattedLastupdatedTime;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "getFormattedLastupdatedTime", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\n			</div>\n		</div>\n	</div>\n	<div class=\"small-3 medium-portrait-3 medium-3 large-2 column actions\">\n		";
  foundHelper = helpers.refreshInProgress;
  stack1 = foundHelper || depth0.refreshInProgress;
  stack2 = helpers['if'];
  tmp1 = self.program(10, program10, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.program(12, program12, data);
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n			\n	</div>\n</div>";
  return buffer;});
templates['siteAccountInfo'] = template(function (Handlebars,depth0,helpers,partials,data) {
  helpers = helpers || Handlebars.helpers;
  var foundHelper, self=this;


  return "<div class=\"row accountStatus\">\n	<div class=\"small-12 medium-12 large-12 column\" id=\"status\">\n	</div>\n</div>\n\n<div id='accounts'></div>";});
return templates;
});
define('10003594_js/views/itemSummaryView',['10003594_js/compiled/finappCompiled'], function(templates) {
	var SiteAccountView = Backbone.Marionette.ItemView.extend({

		initialize : function(options) {
			this.flowType = options.flowType;
			this.model.set('flowType', this.flowType);
			this.moduleKey = options.moduleKey;
			Logger.debug('Site Account View is initialized');
		},
		template: templates['itemSummary'],
		templateHelpers : {
			getStatus : function(){
				var message = "";
				if(this.flowType == 'edit'){
					message = Utilities.getString('status_edited')
				} else if(this.flowType == 'refresh'){
					message = Utilities.getString('status_updated')
				} else {
					message = Utilities.getString('status_added')
				} 
				return message;
			},

			getFormattedLastupdatedTime : function() {
				if(this.flowType == 'edit' || this.flowType == 'refresh') {
					if( this.lastUpdatedTime > 0 ) {
			        	return '| ' +yo.diffDates(moment (this.lastUpdatedTime), moment(), 1);
			    	}
			    }
			}
		}

	});
	return SiteAccountView;
});
define('10003594_js/views/itemSummaryListView',['10003594_js/compiled/finappCompiled', '10003594_js/views/itemSummaryView'], 
	function(templates, siteAccountView) {
	var ItemSummaryListview = Backbone.Marionette.CompositeView.extend({

		initialize : function(options) {
			this.moduleKey = options.moduleKey;
			this.flowType = options.flowType;
			Logger.debug(this.collection.size());
		},

		childViewContainer : '#accounts',

		className: '',

		childView: siteAccountView,
		childViewOptions: function(){
			return {
				flowType : this.flowType
			}
		},

		template: templates['siteAccountInfo']

	});

	return ItemSummaryListview;
});

define('10003594_js/models/header',[], function() {
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
define('10003594_js/views/headerView',['10003594_js/compiled/finappCompiled'], function(templates) {
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
define('10003594_js/views/baseLayoutView',[
    '10003594_js/compiled/finappCompiled',
    '10003594_js/models/header',
    '10003594_js/views/headerView'
    ], 
    function(
        templates, 
        HeaderModel,
        HeaderView ) {
        var BaseLayoutView = Backbone.Marionette.LayoutView.extend({

            className: 'inner-card',

            initialize: function (options) {

                this.headerModel = new HeaderModel(options.siteInfo);
                this.moduleKey = options.moduleKey;
            },

            template: templates['baseLayout'],

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
            }
        });
        return BaseLayoutView;
});

define('10003594_js/views/errorView',['10003594_js/compiled/finappCompiled'], function(templates) {
	var ErrorLayoutView = Backbone.Marionette.LayoutView.extend({

		initialize : function(options) {
			this.siteInfo = options.siteInfo;
			this.siteAccountId = options.siteAccountId;
			this.moduleKey = options.moduleKey;
			this.model.set('siteId', this.siteInfo.siteId);
			this.model.set('displayName', this.siteInfo.displayName);
			this.flowType = options.flowType;
		},

	  	template: templates['errorPage'],

	  	events : {
	  		"click .actionButton" : "actionCategories" 
	  	},

	  	actionCategories : function(evt){
	  		var currentElement = $(evt.target),
	  		actionType = currentElement.prop("id"),
	  		buttonName = currentElement.prop("value");
	  		if(actionType === "TA" || actionType === "UAN" || actionType === "UN"){
	  			this.refreshSite();
	  		} else if(actionType === "EC" || actionType === "UC"){
	  			this.editCredentials();
	  		} else if(actionType === "RC" || actionType === "CP" || 
	  			actionType === "UA" || actionType === "VFY" || 
	  			actionType === "VA" || actionType === "SL" || actionType === "RV"){
	  			this.openLoginUrlWindow();
	  		} else if(actionType === "DA"){
	  			this.deleteAccount();
	  		} else if(actionType === "AMA"){
	  			this.addManualAccount();
	  		} else if(actionType === "CL" || actionType === "UI" || actionType === "VS"){
	  			this.openBaseUrlWindow();
	  		} else if(actionType === "SCS"){
	  			this.addAnotherAccount();
	  		}
	  	},

	  	editCredentials : function(){
	  		Logger.debug(" : "+this.siteAccountId);
	  		Application.AppRouter.route(this.moduleKey, 'loadSiteLoginFormModule', true, 
		  			{ siteInfo : this.siteInfo, siteAccountId : this.siteAccountId, flowType : 'edit' });
	  	},	

	  	refreshSite : function() {
	  		Logger.debug("Force Refresh by user for site Account Id : "+this.siteAccountId);
	  		var data = { 
	  			siteInfo : this.siteInfo, 
	  			siteAccountId : this.siteAccountId, 
	  			refreshAction : 'forceRefresh' 
	  		};

	  		//TODO : If there is flowtype, pass the flowtype as refresh.
	  		if(this.flowType){
	  			data.flowType = 'refresh';
	  		}

	  		Application.AppRouter.route(this.moduleKey, 'loadSiteRefreshStatusModule', true, data);
	  	},

	  	addAnotherAccount : function(){
	  		Logger.debug(" : "+this.siteAccountId);
	  		Application.AppRouter.route(this.moduleKey, 'loadPopularSuggestedSitesModule', true);
	  	},

	  	openBaseUrlWindow : function(){
	  		Application.Wrapper.openPopupWindow(this.siteInfo.baseUrl);
	  	},

	  	openLoginUrlWindow : function(){
	  		Application.Wrapper.openPopupWindow(this.siteInfo.loginUrl);
	  	},

	  	deleteAccount : function(){
	  		alert("Delete Account in progress");
	  	},

	  	addManualAccount : function(){
	  		alert("Add Manual Accoutn in progress");
	  	},
	  	onShow : function() {
			this.$el.find('.error-title').attr('tabindex','0').focus();
		}
	});
	return ErrorLayoutView;
});
define('10003594_js/models/errorModel',[], function() {
  	var ErrorModel = Backbone.Model.extend({
	    defaults : {
	    	errorTitle: "",
	    	errorDescription: "",
	    	siteId : 0,
	    	displayName : ''
	    },

	    initialize : function( options ) {
	    	var args = { '_SITE_DISPLAY_NAME_' : options.siteInfo.displayName,
	    				 '_PRODUCT_NAME_' : Utilities.getString('product_name'),
	    				 '_SUPPORTED_LANGUAGES_' : Utilities.getString('supported_languages') };
	    	if( options.errorMsgKey ) {
	    		this.set('errorDescription', Utilities.getString(options.errorMsgKey, args));
	    	} else {
		    	var errorTitleKey = 'error_'+options.errorCode+'_title';
		    	var errorTitle = Utilities.getString(errorTitleKey, args);
		    	if( errorTitleKey === errorTitle ) {
		    		this.set('errorTitle', Utilities.getString('error_default_title', args));
		    		this.set('errorDescription', Utilities.getString('error_default_desc', args));
		    	} else {
		    		this.set('errorTitle', errorTitle);
		    		this.set('errorDescription', Utilities.getString('error_'+options.errorCode+'_desc', args));
		    	}
		    }
		    this.actionButtonHandler(options);
		    
	    	Logger.debug('Error Code : '+options.errorCode);
    	},

    	actionButtonHandler: function(options){
    		var paramKey = 'errorCode_'+options.errorCode+'_buttons',
		    buttonParams = Utilities.getParam(paramKey),
		    buttonTypes, leftButton, rightButton, leftButtonTextkey, rightButtonTextkey;

		    this.set('actionButtons', buttonParams);
		    if(buttonParams){
		    	if(buttonParams.indexOf(",") != -1){
		    		buttonTypes = buttonParams.split(",");
		    		leftButton = buttonTypes[0],
			    	rightButton = buttonTypes[1];
			    	leftButtonTextkey = 'action_button_'+leftButton+'_text';
			    	rightButtonTextkey = 'action_button_'+rightButton+'_text';
		    	}else{
		    		leftButton = buttonParams,
			    	rightButton = '';
			    	leftButtonTextkey = 'action_button_'+leftButton+'_text';
		    	}
			    this.set('leftButton', leftButton);
			    this.set('rightButton', rightButton);
			    this.set('leftButtonText', Utilities.getString(leftButtonTextkey));
			    if(rightButton){
				    this.set('rightButtonText', Utilities.getString(rightButtonTextkey));
				}
		    }
    	}
  	});
  	return ErrorModel;
});
define('10003594_js/models/siteRefreshStatus',['10003594_js/common/dataParser'], function(DataParser) {
    var SiteRefreshStatus = Backbone.Model.extend({
        defaults : {
            siteRefreshStatusId : -1,
            siteAccountId : 0,
            errorCode : -1
        },

        parse : function( response ) {
            return DataParser.parseSiteRefreshStatus(response);
        }

    });
    return SiteRefreshStatus;
});
define('10003594_js/controller/siteAccountStatusController',['10003594_js/models/siteAccount',
		'10003594_js/collections/itemSummaries',
		'10003594_js/views/itemSummaryListView',
		'10003594_js/common/dataParser',
		'10003594_js/views/baseLayoutView',
		'10003594_js/views/errorView',
		'10003594_js/models/errorModel',
		'10003594_js/models/siteRefreshStatus'
		], 
		function ( 
			SiteAccount,
			ItemSummaries,
			ItemSummaryListView,
			DataParser,
			BaseLayoutView,
			ErrorView,
			ErrorModel,
			SiteRefreshStatus ) {
			var SiteAccountStatusController = Backbone.Marionette.Controller.extend ({
			
			DEFAULT_MAX_POLLING_TIME : 180,

			INFOMATION_MESSAGE_TIME : 10,

			initialize: function(options) {
				Logger.debug('Site Account Status Controller is initialized.');
				this.flowType = options.data.flowType;
	  		},

			start: function(options) {
				var self = this;
				this.region = options.region;
				if( !options.data ) {
					options.data = {};
					options.data.siteInfo = {};
				}

				this.siteInfo = options.data.siteInfo;
				this.siteAccountId = options.data.siteAccountId;
				this.errorCode = options.data.errorCode;
				this.firstCall = true;
				this.pollGetItemsForSite = false;
				this.baseLayoutView = new BaseLayoutView(options.data);
				this.endPollingTime = ((new Date()).getTime() + (this.getMaxPollingConfiguredTime()*1000));
				this.checkSiteRefreshStatus();
				this.region.show(this.baseLayoutView);
				yo.inlineSpinner.show( this.baseLayoutView.content.el );
			},

			checkSiteRefreshStatus : function() {
				var self = this;
            	var result = DataParser.getSiteRefreshInfoInputData(this.siteAccountId);
            	var apiInfo = Application.Wrapper.getAPIDetails(result); 
            	var siteRefreshStatus = new SiteRefreshStatus();
            	Logger.debug(this.siteRefreshStatus);
            	siteRefreshStatus.fetch({
	                type: apiInfo.method,
	                url : apiInfo.url,
	                data: apiInfo.data,
	                success : function(model, response) {
						self.checkRedierctView( model );
					},
	            	error : function(model, error) {
	                    Logger.error('Getting error while checking siterefresh status : '+error);
	                }
	            });
			},

			checkRedierctView : function( model) {
				Logger.debug('Redirect View');
				var self = this;
				this.refreshStatusModel = model;
				console.log(model);
				if( model.get('errorCode') > 0 || model.get('siteRefreshStatusId') == '12') {
					yo.inlineSpinner.hide( this.baseLayoutView.content.el );
	               	this.showErrorView( model.get('errorCode'), model.get('siteRefreshStatusId') );
	            } else {
	           		this.getSiteAccount();
	            }
			},

			getSiteAccount : function() {
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
	                	self.showSuccessView();
						if( self.isStillPolling() ) {
							setTimeout(function() {
								self.getSiteAccount();
							}, 15000);
						}
					},
	                error: function(model, error) {
	                    Logger.error('Getting error while fetching siteaccount data : '+error);
	                },
	                complete : function() {
	                	if( self.baseLayoutView.content ) {
      	                	yo.inlineSpinner.hide( self.baseLayoutView.content.el );
      	                }
	                }
	            });
			},

			isStillPolling : function() {
				var siteRefreshStatusId = this.siteAccount.get('siteRefreshStatus').siteRefreshStatusId;
				if( siteRefreshStatusId == 4 && !this.isMaxPollingLimitCrossed() ) {
					return true;
				}
				return false;
			},

			isMaxPollingLimitCrossed : function() {
				if ( (new Date()).getTime() >= this.endPollingTime ) {
					return true;
				}
				return false;
			},

			getMaxPollingConfiguredTime : function() {
				var timeInSeconds = Utilities.getParam('max_polling_time');
				if( timeInSeconds > 0 ) {
					return timeInSeconds
				}
				return this.DEFAULT_MAX_POLLING_TIME;
			},

			getInformationMessageConfiguredTime : function() {
				var timeInSeconds = Utilities.getParam('information_message_time');
				if( timeInSeconds > 0 ) {
					return timeInSeconds
				}
				return this.INFOMATION_MESSAGE_TIME;
			},


			showSuccessView : function() {
				var self = this;
				if( !this.itemSummaries ) {
					this.itemSummaries = new ItemSummaries();
               		var itemSummaryListView = new ItemSummaryListView({collection: this.itemSummaries, moduleKey : self.moduleKey, flowType : self.flowType });
   	           		this.baseLayoutView.content.show(itemSummaryListView);
   	           		setTimeout( function() {
   	           			self.showInfomationMessage = true;
   	           			self.showSiteRefreshStatusMessage();

   	           		}, this.getInformationMessageConfiguredTime()*1000);
				}
              	if( this.siteAccount.get('itemSummaries') ) {
              		this.itemSummaries.set(this.siteAccount.get('itemSummaries'));
               	} else {
               		Logger.warn('Collection is empty'+ this.siteAccount.get('itemSummaries'));
               	}

               	this.showSiteRefreshStatusMessage( this.itemSummaries.isEmpty() );
			},

			showSiteRefreshStatusMessage : function( isEmptyAccounts ) {
				var errorMessageKey = '';
				var message = '';
				var errorMessage = '';
				if( this.isStillPolling() ) {
					if( !this.showInfomationMessage ) {
						message = '<div class="message">'+Utilities.getString('gathering_transaction_details')+'</div>';
						message += '<div class="icon accountsInProgress"></div>';
					} else {
						message += '<div class="message info">'+Utilities.getString('information_message')+'</div><div class="icon accountsInProgress info"></div>';
					}
					
				} else {
					if( this.siteAccount.get('siteRefreshStatus').siteRefreshStatusId == '4' ) {
						errorMessageKey = 'accountsInErrorMessage_6';
					} else if( !isEmptyAccounts ) {
						if( this.siteAccount.get('isUARError') ) {
							if( this.siteAccount.get('siteRefreshStatus').siteRefreshStatusId == '5' ) {
								errorMessageKey = "accountsInErrorMessage_1";
							}
							
							if( this.siteAccount.get('isAgentError') 
									|| this.siteAccount.get('isSiteError')
									|| this.siteAccount.get('siteRefreshStatus').siteRefreshStatusId == '8' ) {
								if( this.siteAccount.get('siteRefreshStatus').siteRefreshStatusId == '5' ){
									errorMessageKey = "accountsInErrorMessage_4";
								} else if( this.siteAccount.get('siteRefreshStatus').siteRefreshStatusId == '8' ) {
									errorMessageKey = "accountsInErrorMessage_3";
								}
							}
						} else if( this.siteAccount.get('isAgentError') 
								|| this.siteAccount.get('isSiteError') 
								|| this.siteAccount.get('siteRefreshStatus').siteRefreshStatusId == '8' ) {
							if( this.siteAccount.get('siteRefreshStatus').siteRefreshStatusId == '5' ){
								errorMessageKey = "accountsInErrorMessage_4";
							} else if( this.siteAccount.get('siteRefreshStatus').siteRefreshStatusId == '8' ) {
								errorMessageKey = "accountsInErrorMessage_2";
							}
						}
					} else {
						if( this.siteAccount.get('isUARError') ) {
							if( this.siteAccount.get('isAgentError') || this.siteAccount.get('isSiteError')
									|| this.siteAccount.get('siteRefreshStatus').siteRefreshStatusId == '8' ) {
								errorMessageKey = "accountsInErrorMessage_3";
							} else {
								errorMessageKey = "accountsInErrorMessage_1";
							}				
						} else if( this.siteAccount.get('siteRefreshStatus').errorCode == 0 ){
							errorMessageKey = "accountsInErrorMessage_2";
						}
					}
					if( errorMessageKey != '' ) {
						var args = { '_SITE_DISPLAY_NAME_' : this.siteInfo.displayName };
						if(this.flowType == "edit"){
							errorMessageKey = errorMessageKey + '_edit';
						} else if(this.flowType == "refresh"){
							errorMessageKey = errorMessageKey + '_refresh';
						} else {
							errorMessageKey = errorMessageKey + '_add';
						}
						var errorMessage = Utilities.getString(errorMessageKey, args);
						message = '<div class="message">'+errorMessage+'</div><div class="icon yodlee-font-icon svg_error accountsInError"></div>';
					}
				} 

				if( message == '' && this.siteAccount.get('siteRefreshStatus').siteRefreshStatusId == '5') {
					var msg = "";
					if(this.flowType == "edit"){
						msg = Utilities.getString('all_accounts_edited');
					} else if(this.flowType == "refresh"){
						msg = Utilities.getString('all_accounts_updated');
					} else {
						msg = Utilities.getString('all_accounts_added');
					}
					message = '<div class="message">'+ msg +'</div><div class="icon yodlee-font-icon svg_success accountsInSuccess"></div>';
				} else {
					if( isEmptyAccounts ) {
						if( errorMessageKey != '' ) {
	               			this.itemSummaries.set({displayName : this.siteInfo.displayName, errorCode : '-1'})
	               		} else {
	               			this.itemSummaries.set({displayName : this.siteInfo.displayName, refreshInProgress : true})
	               		}
               		}
				}
				this.baseLayoutView.$el.find('#status').html(message);
			},

			showErrorView : function ( errorCode, siteRefreshStatusId ) {
				if( siteRefreshStatusId == '12' ) {
					this.errorMsgKey = 'accountsInErrorMessage_5';
				} else if( this.errorCode > 0 ) {
					Logger.debug('Mfa error code is existed.');
					errorCode = this.errorCode;
				}
				var errormodel = new ErrorModel({ errorCode : errorCode, errorMsgKey : this.errorMsgKey, siteInfo : this.siteInfo });
				var errorview = new ErrorView({
						moduleKey : this.moduleKey, 
						model : errormodel, 
						siteInfo : this.siteInfo,
						siteAccountId : this.siteAccountId});
				this.baseLayoutView.content.show(errorview);
			}
		});
	return SiteAccountStatusController;
});
define('10003594_js/finapp',['10003594_js/controller/siteAccountStatusController'], function(SiteAccountStatusController) {
	var module = Application.Appcore.Module.extend({
		controller : SiteAccountStatusController,

		initialize : function(options) {

		}	

	});
	return module;
});

