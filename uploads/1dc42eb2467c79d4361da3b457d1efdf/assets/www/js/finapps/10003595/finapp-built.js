define('10003595_js/finappConfig',[],function(){ return ({
	dependsJs : ['/js/accountParseHandler.js']
}) });
define('10003595_js/common/dataParser',[], function() {
    
	var DataParser = function() {

		var ACCOUNTS_FOR_SITE = "siteAccountByMemSiteAccId",

		ITEM_SUMMARIES_FOR_CONTAINER = "getItemSummariesForContainer",

		NICK_NAME_KEY = "COM.YODLEE.DISPLAY_OPTION",

		_parseRealStateData = function (response) {
			var parseResponse = {};
			parseResponse.data = {};
			parseResponse.collection = [];
			parseResponse.data.siteId = response[0].contentServiceInfo.contentServiceId.siteId;
			parseResponse.data.siteAccountId = response[0].contentServiceId;
			parseResponse.data.siteDisplayName = Utilities.getString('real_estate');
			parseResponse.data.id = parseResponse.data.siteAccountId;
			parseResponse.id = parseResponse.data.siteAccountId;
			for (var i = response.length - 1; i >= 0; i--) {
				if (response[i].isCustom || response[i].isDisabled) {
					continue;
				}
				var itemdata = response[i].itemData;
				if(itemdata && itemdata.accounts.length) {
					for (var k = itemdata.accounts.length - 1; k >= 0; k--) {
						if (itemdata.accounts[k].itemAccountStatusId === 3 || itemdata.accounts[k].itemAccountStatusId === 2 ) {
							continue;
						}
						parseResponse.collection.push(_parseRealStateItem(itemdata.accounts[k], response[i]));
					};
				}
			};
			parseResponse.data.total = parseResponse.collection.length;
			return parseResponse;
		},

		_parseRealStateItem = function (realstate, responseItem) {
			var item = {},
			lastUpdated;
			item.accountValue = realstate.totalAccountBalance;
			item.accountDisplayName = realstate.accountDisplayName.defaultNormalAccountName; 
			item.accountName = realstate.accountName || responseItem.nickName;
			item.accountNumber = realstate.accountNumber; 
			item.accountType = realstate.accountType || Utilities.getString( 'container_' + responseItem.contentServiceInfo.containerInfo.containerName ) || responseItem.contentServiceInfo.containerInfo.containerName;
			item.lastUpdatedTime = responseItem.secondsSinceLastUpdated;
			item.nickName = responseItem.nickName || item.accountName;
			return item;
		},


		_getSiteAccountsInputData = function (siteAccounts) {
			var result = {};
			result.method = 'POST';
			if (siteAccounts && siteAccounts.siteAccountIds) {
				for (var i = siteAccounts.length - 1; i >= 0; i--) {
					result.data['siteAccountFilter.memSiteAccIds[' + i + ']'] = '' + siteAccounts[i] + '';
				};
			}
			result.data = {'siteAccountFilter.itemSummaryRequired' : '2'};
			result.apiUrl = ACCOUNTS_FOR_SITE;
			return result;	
		},

		_getRealEstateInputData = function () {
			var result = {},
			containerKey = 'container_' + 'RealEstate';
			result.method = 'POST';
			result.data = {'containerName' : Utilities.getString(containerKey)};
			result.apiUrl = ITEM_SUMMARIES_FOR_CONTAINER;
			return result;	
		},

		_getNickNameInputData = function () {
			var args = {};
			args.data = { 'preferenceKey' : NICK_NAME_KEY };
			args.method = 'POST';
			args.apiUrl = 'getMemPrefValue';
			return args;
		},

		_createSite = function (args) {
			var obj= {},
			site = args.site,
			childItems = args.childArray,
			type = args.type;
			if (type === 'inProgress') {
				obj.id = site.siteAccountId;
				obj.siteId = site.siteInfo.siteId;
				obj.siteDisplayName = site.siteInfo.defaultDisplayName;
				obj.siteStatus = site.siteRefreshInfo.siteAddStatus.siteAddStatusId;
				if (args.isPolling) {
					obj.isPolling = args.isPolling;
				}
			} else if (type === 'notAdded' || type === 'added') {
				if (!obj.data) {
					obj.data = {};
				}
				obj.data.siteId = site.siteInfo.siteId;
				obj.data.siteAccountId = site.siteAccountId;
				obj.data.siteDisplayName = site.siteInfo.defaultDisplayName;
				obj.data.id = site.siteAccountId;
				obj.id = site.siteAccountId;
				if (type === 'notAdded') {
					obj.data.isFailed = true;
				}
			}
			if(childItems) {
				obj.collection = childItems;
				obj.data.total = childItems.length
			}
			return obj;
		},

		_parseMyAccountData = function (args) {
			var inProgress = [],
        		addedAccounts = [],
        		notAddedAccounts = [],
        		myAccountsData = [],
        		siteInProgressCode = 13,
        		siteFailedCode = 15,
        		sites = args.response,
        		isNickNameConfig = args.isNickNameConfig,
        		isPolling = args.isAfterPolling;
        		for (var i = sites.length - 1; i >= 0; i--) {
        			var site = sites[i],
    				siteStatus = site.siteRefreshInfo.siteAddStatus,
    				itemSummary = site.itemSummary,
    				isPrePop = Utilities.getParam('show_prepopup_accounts'),
    				siteInProgress =  siteStatus && siteStatus.siteAddStatusId === siteInProgressCode,
    				siteFailed = siteStatus && (siteStatus.siteAddStatusId === siteFailedCode),
    				siteAdded = (!siteInProgress && !siteFailed),
    				accountsArray = [],
					notAddedAccountsArray = [],
					filterObj = {
						isClosedRequired : true,
						isPrePopRequired : isPrePop,
						ignoreContainers : ['RealEstate'] 
					},
					filteredItemSummary = AccountParseHandler.parseAccountsByFilter(itemSummary, filterObj ),
					isRealEstate = site.siteInfo.siteId === 10642;
					if (!isRealEstate) {

						if (filteredItemSummary && filteredItemSummary.length > 0) {
							var accounts;
							for (var j = filteredItemSummary.length - 1; j >= 0; j--) {
								accounts = filteredItemSummary[j].accounts;
								if (accounts && accounts.length) {
									for (var k = accounts.length - 1; k >= 0; k--) {
										if (isNickNameConfig) {
											accounts[k].isNickNameConfig = isNickNameConfig;
										}

										if (_.isUndefined(accounts[k].accountName) && _.isUndefined(accounts[k].nickName)) {
											accounts[k].accountName = accounts[k].accountDisplayName;	
										}
										
										if (!accounts[k].accountType || accounts[k].accountType === 'unknown') {
											accounts[k].accountType = Utilities.getString( filteredItemSummary[j].containerName ) || filteredItemSummary[j].containerName;
										}
										accounts[k].lastUpdatedTime = filteredItemSummary[j].lastUpdatedTime;
										accountsArray.push(accounts[k]);
									};
								} else if (filteredItemSummary[j].errorCode > 0 && filteredItemSummary[j].errorCode !== 801) {
									filteredItemSummary[j].isFailed = true;
									notAddedAccountsArray.push(filteredItemSummary[j]);
								}
							}
						}

						if (accountsArray.length > 0) {
							var addedSite = _createSite ({site : site, childArray : accountsArray, type : 'added'});
							addedAccounts.push(addedSite);
						} 

						if (siteInProgress) {
							var args = {site : site, type : 'inProgress'},
							inProgressAddedSites;
	        				if (isPolling) {
	        					args.isPolling = true;
	        				}
	        				inProgressAddedSites = _createSite (args);
	        				inProgress.push(inProgressAddedSites);
						} 

						if ( notAddedAccountsArray.length > 0 ) {
							var notAddedSites;
							notAddedSites = _createSite ({site : site, type : 'notAdded', childArray : notAddedAccountsArray});
							notAddedAccounts.push(notAddedSites);
						} else if (site.siteRefreshInfo.code > 0 || siteFailed) {
							var notAddedSites = _createSite ({site : site, type : 'notAdded'});
							notAddedAccounts.push(notAddedSites);
						}
					}  				
        		}
        		myAccountsData.push ({'inProgress' : inProgress});
        		myAccountsData.push ({'addedAccounts' : addedAccounts});
        		myAccountsData.push ({'notAddedAccounts' : notAddedAccounts});
        	return myAccountsData;
		},

		_getGraphInputData = function() {
			var graphInput = {},
			index = 0;
			graphInput[index++]  = _getSiteAccountsInputData ();
			graphInput[index++] = _getRealEstateInputData ();
			//graphInput[index++] = _getNickNameInputData ();
			return graphInput;
		};

		return {
	       parseMyAccountData : _parseMyAccountData,
	       parseRealStateData : _parseRealStateData,
	       getSiteAccountsInputData : _getSiteAccountsInputData,
	       getRealEstateInputData : _getRealEstateInputData,
	       getGraphInputData : _getGraphInputData
	    }
	}
	return new DataParser();
});
define('10003595_js/models/myAccount',['10003595_js/common/dataParser'], function(DataParser) {
    var MyAccount = Backbone.Model.extend({});
	return MyAccount;
});
define('10003595_js/collections/myAccounts',['10003595_js/models/myAccount', '10003595_js/common/dataParser'], function(MyAccount, DataParser) {
	var MyAccounts = Backbone.Collection.extend({

		initialize : function (options) {
			this.isNickNameConfig = options.isNickNameConfig;
		},
		
		model : MyAccount,

		parse : function(response) {
			return DataParser.parseMyAccountData({response : response, isNickNameConfig : this.isNickNameConfig, isAfterPolling : false});
		}
	});
  return MyAccounts;
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

define('10003595_js/compiled/finappCompiled',['handlebars'], function(Handlebars) {
  var template = Handlebars.template, templates = Handlebars.templates = Handlebars.templates || {};
templates['accountItem'] = template(function (Handlebars,depth0,helpers,partials,data) {
  helpers = helpers || Handlebars.helpers;
  var buffer = "", stack1, stack2, foundHelper, tmp1, self=this, functionType="function", helperMissing=helpers.helperMissing, undef=void 0, escapeExpression=this.escapeExpression;

function program1(depth0,data) {
  
  var buffer = "", stack1;
  buffer += "\n		";
  stack1 = depth0.nickName;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "this.nickName", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\n	";
  return buffer;}

function program3(depth0,data) {
  
  var buffer = "", stack1;
  buffer += "\n		";
  stack1 = depth0.accountName;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "this.accountName", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\n	";
  return buffer;}

function program5(depth0,data) {
  
  var buffer = "", stack1;
  buffer += "\n	 - ";
  foundHelper = helpers.accountNumber;
  stack1 = foundHelper || depth0.accountNumber;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "accountNumber", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\n	";
  return buffer;}

function program7(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n		";
  foundHelper = helpers.accountValue;
  stack1 = foundHelper || depth0.accountValue;
  foundHelper = helpers.currencyFormat;
  stack2 = foundHelper || depth0.currencyFormat;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "currencyFormat", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\n	";
  return buffer;}

function program9(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n		";
  stack1 = "NA";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\n	";
  return buffer;}

function program11(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n			|\n		";
  foundHelper = helpers.lastUpdatedTime;
  stack1 = foundHelper || depth0.lastUpdatedTime;
  foundHelper = helpers.formatLastUpdatedTime;
  stack2 = foundHelper || depth0.formatLastUpdatedTime;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "formatLastUpdatedTime", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\n	";
  return buffer;}

  buffer += "<div class = \"account-number\">\n	";
  foundHelper = helpers.isNickNameConfig;
  stack1 = foundHelper || depth0.isNickNameConfig;
  stack2 = helpers['if'];
  tmp1 = self.program(1, program1, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.program(3, program3, data);
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n	";
  foundHelper = helpers.accountNumber;
  stack1 = foundHelper || depth0.accountNumber;
  stack2 = helpers['if'];
  tmp1 = self.program(5, program5, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n</div>\n<div class = \"account-type\">\n	";
  foundHelper = helpers.accountType;
  stack1 = foundHelper || depth0.accountType;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "accountType", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\n</div>\n<div class = \"account-balance\">\n	";
  foundHelper = helpers.accountValue;
  stack1 = foundHelper || depth0.accountValue;
  stack2 = helpers['if'];
  tmp1 = self.program(7, program7, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.program(9, program9, data);
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n	";
  foundHelper = helpers.lastUpdatedTime;
  stack1 = foundHelper || depth0.lastUpdatedTime;
  stack2 = helpers['if'];
  tmp1 = self.program(11, program11, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n</div>";
  return buffer;});
templates['inProgressItem'] = template(function (Handlebars,depth0,helpers,partials,data) {
  helpers = helpers || Handlebars.helpers;
  var buffer = "", stack1, stack2, stack3, stack4, foundHelper, tmp1, self=this, functionType="function", helperMissing=helpers.helperMissing, undef=void 0, escapeExpression=this.escapeExpression, blockHelperMissing=helpers.blockHelperMissing;

function program1(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n		<img class = \"siteLogoCls\" style = \"display:none;\"\n		src = \"";
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
  buffer += escapeExpression(stack1) + "\" alt = \"";
  foundHelper = helpers.siteDisplayName;
  stack1 = foundHelper || depth0.siteDisplayName;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "siteDisplayName", { hash: {} }); }
  buffer += escapeExpression(stack1) + " ";
  stack1 = "my_account_logo_text";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\" data =\"";
  foundHelper = helpers.id;
  stack1 = foundHelper || depth0.id;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "id", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\"\n		/>\n	";
  return buffer;}

  buffer += "<div class = \"small-9 medium-9 large-9 column logo-container\">\n	";
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
  buffer += "\n	<div class = \"siteLogoDisplayName\">\n		";
  foundHelper = helpers.siteDisplayName;
  stack1 = foundHelper || depth0.siteDisplayName;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "siteDisplayName", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\n	</div>\n</div>\n<div class = \"small-3 medium-3 large-3 column\">\n	<div class = \"account-inprogress-cls right\"></div>\n</div>";
  return buffer;});
templates['show-no-children-message-template'] = template(function (Handlebars,depth0,helpers,partials,data) {
  helpers = helpers || Handlebars.helpers;
  var buffer = "", stack1, stack2, foundHelper, tmp1, self=this, functionType="function", helperMissing=helpers.helperMissing, undef=void 0, escapeExpression=this.escapeExpression;

function program1(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n\n";
  stack1 = "no_accounts_in_progress_message";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\n";
  return buffer;}

function program3(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n\n";
  stack1 = "no_accounts_added_message";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\n";
  return buffer;}

function program5(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n\n";
  stack1 = "no_accounts_not_added_message";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\n";
  return buffer;}

  foundHelper = helpers.inprogress;
  stack1 = foundHelper || depth0.inprogress;
  stack2 = helpers['if'];
  tmp1 = self.program(1, program1, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n\n";
  foundHelper = helpers.added;
  stack1 = foundHelper || depth0.added;
  stack2 = helpers['if'];
  tmp1 = self.program(3, program3, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n\n";
  foundHelper = helpers.notadded;
  stack1 = foundHelper || depth0.notadded;
  stack2 = helpers['if'];
  tmp1 = self.program(5, program5, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  return buffer;});
templates['siteContainer'] = template(function (Handlebars,depth0,helpers,partials,data) {
  helpers = helpers || Handlebars.helpers;
  var buffer = "", stack1, stack2, stack3, stack4, foundHelper, tmp1, self=this, functionType="function", helperMissing=helpers.helperMissing, undef=void 0, escapeExpression=this.escapeExpression, blockHelperMissing=helpers.blockHelperMissing;

function program1(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n			<div class = \"siteLogoCls\" >\n				<img src=\"";
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
  buffer += escapeExpression(stack1) + "\"\n				alt = \"";
  foundHelper = helpers.siteDisplayName;
  stack1 = foundHelper || depth0.siteDisplayName;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "siteDisplayName", { hash: {} }); }
  buffer += escapeExpression(stack1) + " ";
  stack1 = "my_account_logo_text";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\"/>\n			</div>\n		";
  return buffer;}

function program3(depth0,data) {
  
  var buffer = "", stack1;
  buffer += "\n			<span class = \"total-accounts\">(";
  foundHelper = helpers.total;
  stack1 = foundHelper || depth0.total;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "total", { hash: {} }); }
  buffer += escapeExpression(stack1) + ")</span>\n		";
  return buffer;}

function program5(depth0,data) {
  
  
  return "\n		<div class = \"account-failed-cls yodlee-font-icon svg_error right\"></div>\n		";}

  buffer += "<div class = \"site-cls row\" >\n		";
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
  buffer += "\n		<span class = \"siteLogoDisplayName\" role=\"heading\" aria-level=\"2\">\n			";
  foundHelper = helpers.siteDisplayName;
  stack1 = foundHelper || depth0.siteDisplayName;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "siteDisplayName", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\n		</span>\n		<!--";
  foundHelper = helpers.accountType;
  stack1 = foundHelper || depth0.accountType;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "accountType", { hash: {} }); }
  buffer += escapeExpression(stack1) + "-->\n		";
  foundHelper = helpers.total;
  stack1 = foundHelper || depth0.total;
  stack2 = helpers['if'];
  tmp1 = self.program(3, program3, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n		";
  foundHelper = helpers.isFailed;
  stack1 = foundHelper || depth0.isFailed;
  stack2 = helpers['if'];
  tmp1 = self.program(5, program5, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n</div>\n<div class = \"myAccountItemContainer\">\n	\n</div>";
  return buffer;});
templates['tab/tabContainer'] = template(function (Handlebars,depth0,helpers,partials,data) {
  helpers = helpers || Handlebars.helpers;
  var buffer = "", stack1, stack2, foundHelper, tmp1, self=this, functionType="function", helperMissing=helpers.helperMissing, undef=void 0, escapeExpression=this.escapeExpression;

function program1(depth0,data) {
  
  
  return "\n        active\n      ";}

function program3(depth0,data) {
  
  
  return "\n            aria-selected = \"true\"\n            ";}

function program5(depth0,data) {
  
  
  return "\n            aria-selected = \"false\"\n          ";}

function program7(depth0,data) {
  
  
  return "\n          active\n        ";}

function program9(depth0,data) {
  
  
  return "\n              aria-selected = \"false\"\n              ";}

function program11(depth0,data) {
  
  
  return "\n              aria-selected = \"true\"\n            ";}

function program13(depth0,data) {
  
  
  return "\n          active\n        ";}

function program15(depth0,data) {
  
  
  return "\n        active\n      ";}

  buffer += "<div class=\"hide move-to-added-msg-cls\" aria-hidden = \"true\">\n  <span class = \"yodlee-font-icon svg_success margin-right-cls\"></span>\n  <span class = \"msg-text-container-cls\">\n  ";
  stack1 = "move_to_added_message";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</span>\n</div>\n<ul class=\"tabs customTabs\" id = \"tabs\" data-tab role=\"tablist\">\n    <li class=\"tab-title\n      ";
  stack1 = depth0.isInProgressNotEmpty;
  stack2 = helpers['if'];
  tmp1 = self.program(1, program1, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n      small-4 medium-4 large-4\"\n      role=\"presentation\">\n  	  <a href = \"#panel2-1\"\n        id = \"my_account_in_progress_tab\"\n        aria-controls = \"panel2-1\"\n          ";
  stack1 = depth0.isInProgressNotEmpty;
  stack2 = helpers['if'];
  tmp1 = self.program(3, program3, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.program(5, program5, data);
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n        role=\"tab\"\n        >\n        ";
  stack1 = "inprogress_label";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\n  	  </a>\n    </li>\n    <li class = \"tab-title\n        ";
  stack1 = depth0.isInProgressNotEmpty;
  stack2 = helpers.unless;
  tmp1 = self.program(7, program7, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += " \n        small-4 medium-4 large-4\"\n        role=\"presentation\">\n    		<a href = \"#panel2-2\"\n          aria-controls = \"panel2-2\"\n            ";
  stack1 = depth0.isInProgressNotEmpty;
  stack2 = helpers['if'];
  tmp1 = self.program(9, program9, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.program(11, program11, data);
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n          role=\"tab\"\n          >\n          ";
  stack1 = "add_my_account_label";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\n    		</a>\n    </li>\n    <li class = \"tab-title small-4 medium-4 large-4\" role=\"presentation\">\n    		<a href = \"#panel2-3\"\n        aria-controls=\"panel2-selected\"\n        aria-selected = \"false\"\n        role=\"tab\"\n        >\n        ";
  stack1 = "not_added_my_account_label";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\n    		</a>\n    </li>\n</ul>\n<div class = \"tabs-content fixed-height-cls\" id = \"tabs-content\">\n    <section\n      class = \"content\n        ";
  stack1 = depth0.isInProgressNotEmpty;
  stack2 = helpers['if'];
  tmp1 = self.program(13, program13, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\"\n      id = \"panel2-1\"\n      aria-controls = \"panel2-1\"\n     \n      >\n    </section>\n\n    <section\n    class = \"content\n      ";
  stack1 = depth0.isInProgressNotEmpty;
  stack2 = helpers.unless;
  tmp1 = self.program(15, program15, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\"\n    id = \"panel2-2\"\n    aria-controls = \"panel2-2\"\n   \n    >\n    </section>\n\n    <section\n    class = \"content\"\n    id = \"panel2-3\"\n    aria-controls = \"panel2-3\">\n    </section>\n</div>\n";
  return buffer;});
return templates;
});
define('10003595_js/models/site',['10003595_js/common/dataParser'], function(DataParser) {
    var Site = Backbone.Model.extend({});
	return Site;
});
define('10003595_js/collections/sites',['10003595_js/models/site', '10003595_js/common/dataParser'], function(Site, DataParser) {
	var Sites = Backbone.Collection.extend({
		model: Site,
	    comparator: function(item) {
	      return item.get("data").siteDisplayName.toLowerCase();
	    }
	});
  return Sites;
});
define('10003595_js/models/inProgressItem',['10003595_js/common/dataParser'], function(DataParser) {
    var InProgressItem = Backbone.Model.extend({});
  	return InProgressItem;
});
define('10003595_js/collections/inProgressItems',['10003595_js/models/inProgressItem', '10003595_js/common/dataParser'], function(InProgressItem, DataParser) {
	var InProgressItems = Backbone.Collection.extend({
		model: InProgressItem,
	    comparator: function(item) {
	      return item.get("siteDisplayName").toLowerCase();
	    }
	});
  return InProgressItems;
});
define('10003595_js/views/inProgressItemView',['10003595_js/compiled/finappCompiled'], function(templates) {
	var InProgressItemView = Backbone.Marionette.ItemView.extend({
		initialize : function(options) {
			this.moduleKey = options.moduleKey;
			//Logger.debug('Site Account View is initialized');
		},

		onShow : function () {
			var self = this;
			var logo = this.$el.find('.siteLogoCls');
			if (logo) {
				logo.on('load', function() { self.showHideSiteName() });
			}
		},

		showHideSiteName : function () {
			this.$el.find('.siteLogoCls').show();
			this.$el.find('.siteLogoDisplayName').attr('aria-hidden', true).hide();
		},

		/*showMovedMessage : function () {
			var self = this;
			this.$el.addClass('opacity-cls');
			this.$el.find('.move-to-added-msg-cls').removeClass('hide');
			setTimeout(function () {
				self.$el.fadeOut('slow');
			}, 1000);
		},*/
		
		className : 'inprogress-item row',

		template : templates['inProgressItem']
	});
	return InProgressItemView;
});
define('10003595_js/views/noChildsView',['10003595_js/compiled/finappCompiled'], function(templates) {
	var NoChildsView = Backbone.Marionette.ItemView.extend({
		initialize : function(options) {
			this.moduleKey = options.moduleKey;
			if (options.inprogress) {
				this.model.set('inprogress', true);
            } else if (options.added) {
				this.model.set('added', true);
            } else if (options.notadded) {
				this.model.set('notadded', true);
            }
			//Logger.debug('Site Account View is initialized');
		},

		className : "text-center empty-view",

		//attributes : {tabindex : "0", role : "alert"},

		template: templates['show-no-children-message-template']
	});
	return NoChildsView;
});
define('10003595_js/views/inProgressCollectionView',['10003595_js/compiled/finappCompiled',
    '10003595_js/views/inProgressItemView',
    '10003595_js/views/noChildsView'
    ],
    function (
        templates,
        InProgressItemView,
        NoChildsView) {
        var InProgressCollectionView = Backbone.Marionette.CollectionView.extend({

            initialize: function ( options ) {
                this.addSiteAccounts = [];
            },

            emptyViewOptions : function ( options ) {
                var obj = {};
                if (this.options.inprogress) {
                    obj.inprogress = true;
                } else if (this.options.added) {
                    obj.added = true;
                } else if (this.options.notadded) {
                    obj.notadded = true;
                }
                return obj;
            },
            
            emptyView : NoChildsView,

            childView : InProgressItemView,

            onBeforeRemoveChild : function ( childView ) {
                //childView.$el.addClass( 'disabledSite' );
                /*var isEmptyView = childView.$el.hasClass('empty-view');
                if (!isEmptyView) {
                    childView.showMovedMessage(childView);
                }*/
            },

            onRemoveChild : function ( childView ) {
                var isEmptyView = childView.$el.hasClass('empty-view');
                if (!isEmptyView) {
                    this.removesiteIdFromSiteAccountsArray(childView.model.get('siteAccountId'));
                }
                if (this.collection.length === 0) {
                    if (this.setinterval) {
                        clearInterval (this.setinterval);
                    }
                    this.addSiteAccounts = [];
                }
            },

            onAddChild : function ( childView ) {
                var timmer = parseInt(Utilities.getParam('my_account_polling_time')) * 1000;
                this.addSiteAccounts.push(childView.model.get('siteAccountId'));
                if (this.collection.length > 0 && timmer && !this.setinterval) {
                    this.setinterval = setInterval(function() { Backbone.trigger('fetchdata:myAccountPollingEvent'); }, timmer);
                }
                childView.$el.attr({id : childView.model.get('id')});
                if (childView.model.get('isPolling')) {
                    childView.$el.addClass('afterPolling');
                }
            },

            getAllInProgressSiteAccountId : function () {
                return this.addSiteAccounts;
            },

            removesiteIdFromSiteAccountsArray : function (siteaccountid) {
                _.reject(this.addSiteAccounts, function(num){ return num === siteaccountid; });
            },

            onBeforeDestroy : function () {
                if (this.setinterval) {
                    clearInterval (this.setinterval);
                }
            }
        });
    return InProgressCollectionView;
});
define('10003595_js/models/account',['10003595_js/common/dataParser'], function(DataParser) {
    var Account = Backbone.Model.extend({
	});
	return Account;
});
define('10003595_js/collections/accounts',['10003595_js/models/account', '10003595_js/common/dataParser'], function(Account, DataParser) {
	var Accounts = Backbone.Collection.extend({
		model : Account,
	    comparator: function(item) {
	      return item.get("accountName").toLowerCase();
	    }
	});
  return Accounts;
});
define('10003595_js/views/accountItemView',['10003595_js/compiled/finappCompiled'], function(templates) {
	var AccountItemView = Backbone.Marionette.ItemView.extend({
		initialize : function(options) {
			this.moduleKey = options.moduleKey;
			Logger.debug('Site Account View is initialized');
		},
		
		className: 'list-item',

		template: templates['accountItem']
	});
	return AccountItemView;
});
define('10003595_js/models/siteHeader',['10003595_js/common/dataParser'], function(DataParser) {
	var SiteHeader = Backbone.Model.extend({});
	return SiteHeader;
});
define('10003595_js/views/siteCompositeView',['10003595_js/compiled/finappCompiled',
 '10003595_js/collections/accounts',
 '10003595_js/views/accountItemView',
 '10003595_js/models/siteHeader'], 
	function(templates,
	AccountsCollection,
	accountItemView,
	headerModel) {
	var SiteCompositeView = Backbone.Marionette.CompositeView.extend({

		initialize : function(options) {
			this.moduleKey = options.moduleKey;
			this.model = new headerModel(options.model.get('data'));
			this.collection = new AccountsCollection (options.model.get('collection'));
		},

		childViewContainer : '.myAccountItemContainer',

		className: 'added-site-account-cls',

		childView: accountItemView,

		template: templates['siteContainer'],

		templateHelpers: function() {
    		return { items: this.collection.toJSON() };
  		},
  		
  		onShow : function () {
			var self = this;
			var logo = this.$el.find('.siteLogoCls img');
			if (logo) {
				logo.on('load', function() { self.showHideSiteName() });
			}
		},

		showHideSiteName : function () {
			this.$el.find('.siteLogoCls').addClass('inline-cls').show();
			this.$el.find('.siteLogoDisplayName').hide();
		},
	});

	return SiteCompositeView;
});
define('10003595_js/views/sitesCollectionView',[
    '10003595_js/compiled/finappCompiled',
    '10003595_js/views/siteCompositeView',
    '10003595_js/views/noChildsView'
    ],
    function (
        templates,
        SiteCompositeView,
        NoChildsView) {
        var SitesCollectionView = Backbone.Marionette.CollectionView.extend({

            initialize: function (options) {
                this.options = options;
            },

            emptyView : NoChildsView,

            emptyViewOptions : function (options) {
                var obj = {};
                if (this.options.inprogress) {
                    obj.inprogress = true;
                } else if (this.options.added) {
                    obj.added = true;
                } else if (this.options.notadded) {
                    obj.notadded = true;
                }
                return obj;
            },

            childView : SiteCompositeView
        });
    return SitesCollectionView;
});
define('10003595_js/views/tabs/tab',['10003595_js/compiled/finappCompiled',
 '10003595_js/collections/sites',
 '10003595_js/collections/inProgressItems',
 '10003595_js/views/inProgressCollectionView',
 '10003595_js/views/sitesCollectionView'],
	function(templates,
	Sites,
	InProgressCollection,
	InProgressCollectionView,
	SitesCollectionView) {
	var Tabs = Backbone.Marionette.LayoutView.extend({

		initialize : function(options) {
			this.moduleKey = options.moduleKey;
			this.inProgressCollection = new InProgressCollection (options.inProgressData);
			this.addedSitesCollection = new Sites(options.addedAccountsData);
			this.notAddedSitesCollection = new Sites(options.notAddedData);
		},

		regions : {
            inProgress : "#panel2-1",
            added : "#panel2-2",
            notAdded : "#panel2-3"
        },

		template : templates['tab/tabContainer'],

		className : 'my-account-container',

		addInProgress : function () {

		},

		onBeforeShow : function () {
			this.inProgressCollectionView = new InProgressCollectionView({collection : this.inProgressCollection, inprogress : true});
			this.addedSitesView = new SitesCollectionView ({collection : this.addedSitesCollection, added : true});
			this.notAddedSitesView = new SitesCollectionView ({collection : this.notAddedSitesCollection, isNotAdded : true, notadded : true});
		},

		onShow : function () {
			var self = this;
			$(document).foundation({
				tab: {
			      callback : function (tab) {
			      	$('.tabs li').find('a').attr ('aria-selected', false);
			      	tab.find('a').attr('aria-selected', true);
			      }
			    }
    		});
			this.inProgress.show(this.inProgressCollectionView);
			this.added.show(this.addedSitesView);
			this.notAdded.show(this.notAddedSitesView);
		}
	});
	return Tabs;
});
define('10003595_js/controller/myAccountController',['10003595_js/common/dataParser',
		'10003595_js/collections/myAccounts',
		'10003595_js/views/tabs/tab'
		],
		function (
			DataParser,
			MyAccountsCol,
			Tabs
			) {
			var MyAccountsController = Backbone.Marionette.Controller.extend ({
			
			initialize: function(options) {
				if (Utilities.getParam('my_account_polling_time') > 0) {
		    		this.listenTo( Backbone, 'fetchdata:myAccountPollingEvent', this.fetchInProgressData, this );
				}
	  		},

			start: function(options) {
				//Logger.debug('10003595 start method::');
				var self = this;
				this.region = options.region;
				if( !options.data ) {
					options.data = {};
				}
				yo.inlineSpinner.show(this.region.el);
				this.getGraphData();
			},

			getGraphData : function() {
			    //Logger.debug("Calling graph data for 10003595::");
			    var self = this;
			    var graphInputData = DataParser.getGraphInputData();
			    graphInputData = Application.Wrapper.formatGraphInputData(graphInputData); 
			    Application.YGraph.build( graphInputData, function( graphData ) {
			        self.renderSites( graphData['InternalPassThroughMakeCall_siteAccountByMemSiteAccId'], graphData['InternalPassThroughMakeCall_getMemPrefValue'] );
			        self.renderRealEstate( graphData['InternalPassThroughMakeCall_getItemSummariesForContainer'] );
			    });
			},

			/*fetchNickNameStatus : function () {
				var self = this;
				Utilities.getMemPrefValue(NICK_NAME_KEY, function(response) { self.fetchData(response) });
			},*/

			renderSites : function (response, nickNameResponse) {
				//Logger.debug('10003595 renderSites::');
				var self = this,
				isNickNameConfig = false,
				inProgressModel,
				addedModel,
				notAddedModel,
				isInProgressNotEmpty;
				/*if (nickNameResponse) {
					isNickNameConfig = nickNameResponse.value;
				}*/
				if ( !this.myAccountsCollection ) {
	            	this.myAccountsCollection = new MyAccountsCol({isNickNameConfig : isNickNameConfig});
	            }
	            filteredResponse = DataParser.parseMyAccountData({response : response, isNickNameConfig : isNickNameConfig, isAfterPolling : false});
	            this.myAccountsCollection.set(filteredResponse);
				inProgressData = filteredResponse[0].inProgress;
				addedData = filteredResponse[1].addedAccounts;
				notAddedData = filteredResponse[2].notAddedAccounts;
				isInProgressNotEmpty = !!inProgressData.length;
				yo.inlineSpinner.hide(self.region.el);
				if (!self.tabs) {
					self.tabs = new Tabs ({
						inProgressData : inProgressData,
						addedAccountsData : addedData,
						notAddedData : notAddedData,
						model : new Backbone.Model({'isInProgressNotEmpty' : isInProgressNotEmpty, 'isNickNameConfig' : isNickNameConfig})
					});
					self.region.show(self.tabs);
				}
			},

			renderRealEstate : function (response) {
				var realEstate;
				//Logger.debug('renderRealEstate ::');
				if ( _.isArray(response) && response.length > 0 ) {
					realEstate = DataParser.parseRealStateData(response);
					this.tabs.addedSitesCollection.add(realEstate);
				}
				this.realEstate = realEstate;
			},

			fetchInProgressData : function () {
				var siteAccountIds,
				inProgressCollectionView = this.tabs.inProgressCollectionView,
				siteAccountIds = inProgressCollectionView.getAllInProgressSiteAccountId(),
				result = DataParser.getSiteAccountsInputData({siteAccountIds : siteAccountIds}),
				apiInfo = Application.Wrapper.getAPIDetails(result),
				self = this;
				apiInfo.success = function (response) {
					self.renderInprogressTab (response);
				};
				Utilities.makeAPICall (apiInfo);
			},

			renderInprogressTab : function (response) {
				var updatedData = DataParser.parseMyAccountData ({response : response, isAfterPolling : true}),
				inProgressArr = updatedData[0].inProgress,
				addedAccountsArr = updatedData[1].addedAccounts,
				notAddedAccountsArr = updatedData[2].notAddedAccounts,
				oldInProgressIds = _.pluck(this.tabs.inProgressCollection.toJSON(), 'id').join(),
				oldAddedAccountsIds = _.pluck(this.tabs.addedSitesCollection.toJSON(), 'id').join(),
				oldNotAddedAccountsIds = _.pluck(this.tabs.notAddedSitesCollection.toJSON(), 'id').join(),
				newInProgressIds = _.pluck(inProgressArr, 'id').join(),
				newAddedAccountsIds = _.pluck(addedAccountsArr, 'id').join(),
				newNotAddedAccountsIds = _.pluck(notAddedAccountsArr, 'id').join(); 
				if (oldInProgressIds.length === 0 ) {
					this.tabs.inProgressCollection.set(inProgressArr);
				} else if (!!oldInProgressIds.localeCompare(newInProgressIds)) {
					this.tabs.inProgressCollection.add(inProgressArr);
					var removedIdsArr  = _.difference(oldInProgressIds.split(','), newInProgressIds.split(',')),
					self = this;
					if (removedIdsArr.length > 0) {
						$.each(removedIdsArr, function(index, element) {
							var id = element,
							elm = $('#' + element),
							addedIds = _.pluck(addedAccountsArr, 'id').join(),
							notAddedIds = _.pluck(notAddedAccountsArr, 'id').join(),
							notAddedString = Utilities.getString('move_to_not_added_message'),
							moveToMsgElm = self.tabs.$el.find('.move-to-added-msg-cls'),
							isInAdded = false;
							if(addedIds.length > 0 && addedIds.indexOf(id)  === 0) {
								isInAdded = true;
							}
							if (!isInAdded) {
								moveToMsgElm.find('.msg-text-container-cls').text(notAddedString);
							}
							moveToMsgElm.removeClass('hide').css({top : (elm.position().top + elm.height()/2) + 2});
							elm.addClass('opacity-cls');
							setTimeout(function() {
								moveToMsgElm.addClass('hide');
								self.tabs.inProgressCollection.remove(self.tabs.inProgressCollection.get(id));
							}, 1500);
						});
					}
				}
							
				this.tabs.addedSitesCollection.set(addedAccountsArr);
				if (this.realEstate) {
					this.tabs.addedSitesCollection.add(this.realEstate);
				}
				this.tabs.notAddedSitesCollection.set(notAddedAccountsArr);
			},

			addedSiteAccount : function (options) {
				var view = this.tabs.inProgressCollectionView,
				inProgressTab = $('#panel2-1'),
				isInProgressTabVisible = inProgressTab.is(':visible'),
				model = new view.collection.model({
					siteDisplayName : options.siteInfo.displayName,
					siteId : options.siteInfo.siteId,
					siteAccountId : options.siteAccountId,
					id : options.siteAccountId
				});
				view.collection.add(model);
				if (!isInProgressTabVisible) {
					$('#my_account_in_progress_tab').trigger('click');
				}
			}
		});
	return MyAccountsController;
});
define('10003595_js/finapp',['10003595_js/controller/myAccountController'], function(MyAccountController) {
	var module = Application.Appcore.Module.extend({
		controller : MyAccountController,

		initialize : function(options) {
			Logger.debug('MyAccountController is intialized')
		},

		events : {
			'ADDED_SITE_ACCOUNT' : 'addedSiteAccount'
		}

	});
	return module;
});

