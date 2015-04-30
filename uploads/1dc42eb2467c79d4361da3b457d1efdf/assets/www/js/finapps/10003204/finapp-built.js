define('10003204_js/finappConfig',[],function(){ return ({
	"id" : "10003204",
	"name":"Timely",
	"version" : "src",
	"dependsModule":["10003507"],//remove if you don't want it to load 10003507 inside Timely container and want to change the moduleSwitch
	"dependsJs": ["/js/chart/highcharts_v4_0_1.js"],
	"modules" : [
		{
			"id" : "10003403",
			"name" : "Accounts",
			"version" : "src",
		},
		{
			"id" : "10003507",
			"name" : "Transactions",
			"version" : "src",
		}
	]
}); });
define('10003204_js/models/TimelyModel',[],function(){
   var TimelyModel = Backbone.Model.extend({  
    });
    return TimelyModel;
});

define('10003204_js/collections/TimelyCollection',['10003204_js/models/TimelyModel'],function(TimelyModel){
    var TimelyCollection = Backbone.Collection.extend({
        model: TimelyModel
    });
    return TimelyCollection;
});


define('10003204_js/models/UserNotificationModel',['10003204_js/models/UserNotificationModel'],function(){
   var UserNotificationModel = Backbone.Model.extend({});
    return UserNotificationModel;
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

define('10003204_js/compiled/finappCompiled',['handlebars'], function(Handlebars) {
  var template = Handlebars.template, templates = Handlebars.templates = Handlebars.templates || {};
templates['UserNotifications'] = template(function (Handlebars,depth0,helpers,partials,data) {
  helpers = helpers || Handlebars.helpers;
  var buffer = "", stack1, stack2, foundHelper, tmp1, self=this, functionType="function", helperMissing=helpers.helperMissing, undef=void 0, escapeExpression=this.escapeExpression, blockHelperMissing=helpers.blockHelperMissing;

function program1(depth0,data) {
  
  
  return "\n			<dl class='accordion'>\n				<dd class='accordion-navigation'>\n					<div class='clearfix row-middle'>\n						<div class='clearfix'>\n							<div class='textEntry'>\n								Push\n							</div>\n							<div class='right'>\n								<div class='switch'>\n									<input  id='userNotificationsSwitch_push' type='checkbox'>\n									<label for='userNotificationsSwitch_push'><p class='toggleText'>OFF</p></label>\n								</div>\n							</div>\n						</div>\n					</div>\n				</dd>\n			</dl>\n			";}

  buffer += "<div class=\"userNotificationSettings\">\n\n	<div class=\"pageheader\">\n		<div class=\"panel-sub-title text-center\">";
  stack1 = "Notification Settings";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</div>\n	</div>\n	<span class=\"leftArrow\" title=\"";
  stack1 = "back";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\" onclick=\"yo.NG.hideSearchContainers()\"></span>\n\n	<div class=\"settingsView\">\n\n		<h3>Notification Settings</h3>\n\n\n		<div class=\"uiBoxCluster\">\n			<dl class='accordion'>\n				<dd class='accordion-navigation'>\n					<div class='clearfix row-middle row-heading'>\n						<div class='clearfix'>\n							<div class='textEntry'>\n								Methods\n							</div>\n						</div>\n					</div>\n				</dd>\n			</dl>\n			<dl class='accordion'>\n				<dd class='accordion-navigation'>\n					<div class='clearfix row-middle'>\n						<div class='clearfix'>\n							<div class='textEntry'>\n								E-mail\n							</div>\n							<div class='right'>\n								<div class='switch'>\n									<input  id='userNotificationsSwitch_email' type='checkbox'>\n									<label for='userNotificationsSwitch_email'><p class='toggleText'>OFF</p></label>\n								</div>\n							</div>\n						</div>\n					</div>\n				</dd>\n			</dl>\n			<dl class='accordion'>\n				<dd class='accordion-navigation'>\n					<div class='clearfix row-middle'>\n						<div class='clearfix'>\n							<div class='textEntry'>\n								SMS\n							</div>\n							<div class='right'>\n								<div class='switch'>\n									<input  id='userNotificationsSwitch_sms' type='checkbox'>\n									<label for='userNotificationsSwitch_sms'><p class='toggleText'>OFF</p></label>\n								</div>\n							</div>\n						</div>\n					</div>\n				</dd>\n			</dl>\n			";
  foundHelper = helpers.showPushSettings;
  stack1 = foundHelper || depth0.showPushSettings;
  tmp1 = self.program(1, program1, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  if(foundHelper && typeof stack1 === functionType) { stack1 = stack1.call(depth0, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack1, tmp1); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n		</div><!-- END div.uiBoxCluster TOP -->\n\n		<dl class=\"accordion\">\n			<dd class=\"accordion-navigation\">\n				<h4>Credit Card Balance</h4>\n			</dd>\n		</dl>\n\n		<div class=\"uiBoxCluster\">\n			<dl class='accordion'>\n				<dd class='accordion-navigation'>\n					<div class='clearfix row-middle'>\n						<div class='clearfix'>\n							<div class='textEntry'>\n								Cumulative Balance\n							</div>\n							<div class='right'>\n								<div class='switch' onclick='handleSettingSwitch(this)'>\n									<input  id='userNotificationsSwitch_totalbalance' type='checkbox'>\n									<label for='userNotificationsSwitch_totalbalance'><p class='toggleText'>OFF</p></label>\n								</div>\n							</div>\n							<div class='clearfix settingAdjusters settingInactive' id='userNotificationsSwitch_totalbalance_Target'>\n								<div class='adjustText'>Notify me when my credit card balance across all cards exceeds:</div>\n								<div class='pctSignBox'><input type='tel' name='limit' id='limitPct' maxlength='3' onkeydown='return inputNumPct.filter(this,event)' onkeyup='inputNumPct.bound(this)' onblur='inputNumPct.finish(this)' onfocus='inputNumPct.init()' voidvalue='30%' voidmin='1' voidmax='100' class='adjustTextbox' value='30%' disabled /><span class='pctSignSymbol' style='' id='limitPctSymbol' onclick='inputNumPct.invoke()'>%</span></div>\n							</div>\n						</div>\n						<div class='adjustInfoText' id='userNotificationsSwitch_totalbalance_nomobile'>\n							A cumulative credit card balance of over 30% will affect your credit score negatively. \n							Turn on to receive an alert when your cumulative balance goes over a certain percentage.\n						</div>\n					</div>\n				</dd>\n			</dl>\n		</div><!-- END div.uiBoxCluster BOTTOM -->\n\n\n	</div><!-- END div.settingsView -->\n\n</div><!-- END div.userNotificationSettings -->\n\n";
  return buffer;});
templates['main'] = template(function (Handlebars,depth0,helpers,partials,data) {
  helpers = helpers || Handlebars.helpers;
  var buffer = "", stack1, stack2, stack3, stack4, foundHelper, tmp1, self=this, functionType="function", helperMissing=helpers.helperMissing, undef=void 0, escapeExpression=this.escapeExpression, blockHelperMissing=helpers.blockHelperMissing;

function program1(depth0,data) {
  
  var buffer = "", stack1, stack2, stack3, stack4;
  buffer += "\n	<div class=\"options-bar toolbar-main\">\n		<div class=\"main-logo-left\">";
  foundHelper = helpers.bankLogo;
  stack1 = foundHelper || depth0.bankLogo;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "bankLogo", { hash: {} }); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += " <span class=\"finapp-logo-text\">";
  stack1 = "Financial Fitness";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</span></div>\n		<div class=\"main-btn-bar-right\">\n			<div class=\"btn-list\">\n				";
  stack1 = "true";
  stack2 = "==";
  stack3 = "showSearch";
  foundHelper = helpers.ifCond;
  stack4 = foundHelper || depth0.ifCond;
  tmp1 = self.program(2, program2, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  if(foundHelper && typeof stack4 === functionType) { stack1 = stack4.call(depth0, stack3, stack2, stack1, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack4, stack3, stack2, stack1, tmp1); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n				\n				<div id=\"mobileSettings\">\n					<span tabindex=\"0\" role=\"button\" class=\"settingsIcon\" data-reveal-id=\"settings_options\">\n						<span class=\"mobileText\">...</span>\n					</span>\n					<div id=\"settings_options\" class=\"reveal-modal toolTip\" data-reveal=\"\">\n						<div class=\"triangleBorder\"></div>\n						<div class=\"triangle\"></div>\n						<div class=\"modal-link accts\" tabindex=\"0\" role=\"button\" onclick=\"yo.NG.loadUserSettings()\" onkeyup=\"if(yo.enter(event)){yo.NG.loadUserSettings()}\">\n						";
  foundHelper = helpers.acctsIcon;
  stack1 = foundHelper || depth0.acctsIcon;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "acctsIcon", { hash: {} }); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n						";
  stack1 = "ACCOUNTS";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "<span class=\"ada-offscreen\"> ";
  stack1 = "Loads Accounts Page Below";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</span></div>\n						";
  foundHelper = helpers.switchEnableNotificationSettings;
  stack1 = foundHelper || depth0.switchEnableNotificationSettings;
  tmp1 = self.program(4, program4, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  if(foundHelper && typeof stack1 === functionType) { stack1 = stack1.call(depth0, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack1, tmp1); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n					</div>\n				</div>\n				\n				";
  stack1 = "true";
  stack2 = "==";
  stack3 = "showSearch";
  foundHelper = helpers.ifCond;
  stack4 = foundHelper || depth0.ifCond;
  tmp1 = self.program(6, program6, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  if(foundHelper && typeof stack4 === functionType) { stack1 = stack4.call(depth0, stack3, stack2, stack1, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack4, stack3, stack2, stack1, tmp1); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n				\n				<div id=\"tasksAndAccountMenuBar\">\n					";
  stack1 = "true";
  stack2 = "==";
  stack3 = "showTasks";
  foundHelper = helpers.ifCond;
  stack4 = foundHelper || depth0.ifCond;
  tmp1 = self.program(8, program8, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  if(foundHelper && typeof stack4 === functionType) { stack1 = stack4.call(depth0, stack3, stack2, stack1, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack4, stack3, stack2, stack1, tmp1); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n					<a tabindex=\"0\" role=\"button\" href=\"#\" title=\"";
  stack1 = "Go to account details";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\" onclick=\"yo.NG.loadUserSettings()\" onkeyup=\"if(yo.enter(event)){yo.NG.loadUserSettings()}\" class=\"btn-link account\">\n						<span class=\"dots\">...</span>\n						<span class=\"small-menu-btn animateMed\">";
  stack1 = "MORE";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "<span class=\"ada-offscreen\"> ";
  stack1 = "Go to account details";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</span></span>\n					</a>\n				</div>\n			</div>\n		</div>\n	</div>\n	";
  return buffer;}
function program2(depth0,data) {
  
  
  return "\n					<script>\n						yo.getTaskMenuHtml('tasksAndAccountMenuBar');\n					</script>\n				";}

function program4(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n						<div class=\"modal-link vertical bell\" tabindex=\"0\" role=\"button\" onclick=\"yo.showNotifications()\" onkeyup=\"if(yo.enter(event)){yo.showNotifications()}\">";
  stack1 = "NOTIFICATION SETTINGS";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</div>\n						";
  return buffer;}

function program6(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n					<a tabindex=\"0\" role=\"button\" href=\"#\" class=\"btn-link search\" id=\"searchLink\" onclick=\"yo.NG.showSearch(this);\" onkeyup=\"if(yo.enter(event)){yo.NG.showSearch(this);}\" >\n						<span class=\"searchIcon\">";
  foundHelper = helpers.searchIcon;
  stack1 = foundHelper || depth0.searchIcon;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "searchIcon", { hash: {} }); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "</span>\n						<span class=\"small-menu-btn animateMed\" title=\"";
  stack1 = "SEARCH";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\">";
  stack1 = "SEARCH";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "<span class=\"ada-offscreen\"> ";
  stack1 = "content";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + ". ";
  stack1 = "Opens new dialogue";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</span></span>\n					</a>\n				";
  return buffer;}

function program8(depth0,data) {
  
  var buffer = "", stack1, stack2, stack3, stack4;
  buffer += "\n						\n						<a tabindex=\"0\" role=\"button\" id=\"tasks\" href=\"#\" title=\"";
  stack1 = "TASKS";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\" class=\"btn-link tasks\" data-reveal-id=\"taskmenu\">\n							";
  foundHelper = helpers.crossHairsIcon;
  stack1 = foundHelper || depth0.crossHairsIcon;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "crossHairsIcon", { hash: {} }); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n							<span class=\"small-menu-btn animateMed\"><span class=\"ada-offscreen\">";
  stack1 = "Perform";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + " </span>";
  stack1 = "TASKS";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "<span class=\"ada-offscreen\"> ";
  stack1 = "Opens new dialogue";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</span></span>\n			            </a>\n			            ";
  stack1 = "true";
  stack2 = "==";
  stack3 = "showAddAnAccountLink";
  foundHelper = helpers.ifCond;
  stack4 = foundHelper || depth0.ifCond;
  tmp1 = self.program(9, program9, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  if(foundHelper && typeof stack4 === functionType) { stack1 = stack4.call(depth0, stack3, stack2, stack1, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack4, stack3, stack2, stack1, tmp1); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n		          	";
  return buffer;}
function program9(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n							<a href=\"#\" data-js=\"message\" data-message=\"invokeAddAccountLink\" title=\"";
  stack1 = "ACCOUNT";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\" class=\"btn-link account\"></a>\n						";
  return buffer;}

function program11(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n			<script>yo.getSearchHtml('searchDivider');</script>\n			\n			<div id=\"searchDivider\" class=\"clearfix\"></div>\n			\n			<div id=\"advancedSearch\">\n				<div id=\"filtersBar\">\n					<div class=\"center dropContain\" onclick=\"if(event.srcElement){event.target=event.srcElement;}if(event.target.className.indexOf('dropContain')!=-1){yo.closeDropdownSearch();}\">\n						<div id=\"dateFilter\" role=\"combobox\" class=\"filterBox\" onclick=\"yo.NG.showDateFilter(this);\" onkeyup=\"if(yo.enter(event)){yo.NG.showDateFilter(this);}\" tabindex=\"1\">\n							<span>";
  stack1 = "DATE";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</span>\n							<span class=\"filterChevron\">\n								";
  foundHelper = helpers.smallDownAndUpArrow;
  stack1 = foundHelper || depth0.smallDownAndUpArrow;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "smallDownAndUpArrow", { hash: {} }); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n							</span>\n						</div>\n						<div id=\"amountFilter\" role=\"combobox\" class=\"filterBox\" onclick=\"yo.NG.showAmountFilter(this);\" onkeyup=\"if(yo.enter(event)){yo.NG.showAmountFilter(this);}\" tabindex=\"1\">\n							<span>";
  stack1 = "AMOUNT";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</span>\n							<span class=\"filterChevron\">\n								";
  foundHelper = helpers.smallDownAndUpArrow;
  stack1 = foundHelper || depth0.smallDownAndUpArrow;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "smallDownAndUpArrow", { hash: {} }); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n							</span>\n						</div>\n						<div id=\"categoryFilter\" role=\"combobox\" class=\"filterBox\" onclick=\"if(event.srcElement){event.target=event.srcElement;}yo.openDropdownSearch(event.target,__['CATEGORY'],yo.dropdownSearchData,'yo.NG.doCategorySearch(this)');\"  onkeyup=\"if(yo.enter(event)){if(event.srcElement){event.target=event.srcElement;}yo.openDropdownSearch(event.target,__['CATEGORY'],yo.dropdownSearchData,'yo.NG.doCategorySearch(this)');}\" tabindex=\"1\">\n							<span>";
  stack1 = "CATEGORY";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</span>\n							<span class=\"filterChevron\">\n								";
  foundHelper = helpers.smallDownAndUpArrow;
  stack1 = foundHelper || depth0.smallDownAndUpArrow;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "smallDownAndUpArrow", { hash: {} }); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n							</span>\n						</div>\n						\n						<div class=\"dropdowns\">\n							<div id=\"dateFilterDropdown\">\n								<div class=\"errorMsg\">The start date must be before the end date.</div>\n								<div class=\"from\"> \n									<span class=\"lbl\">";
  stack1 = "Start";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</span>\n									<input onpaste=\"return false;\" type=\"text\" id=\"fromDate\" class=\"desktop dateInput\" onchange=\"yo.NG.doDateSearch();\" onkeypress=\"return false;\" onclick=\"yo.NG.showHideCalendar('fromCalendarPicker')\" title=\"Start date\"/>\n									<input onpaste=\"return false;\" type=\"date\" name=\"date\" id=\"fromDate\" class=\"mobile dateInput\" onclick=\"yo.NG.unresize();\" onkeyup=\"yo.NG.unresize();\" onchange=\"yo.NG.doDateSearch();yo.NG.unresize();\" title=\"Start date\"/>\n									<div id=\"fromCalendarPicker\" class=\"calendarPicker\"></div>\n								</div>\n								<div class=\"to\" style=\"clear:both;\"> \n									<span class=\"lbl\">";
  stack1 = "End";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</span>\n									<input onpaste=\"return false;\" type=\"text\" id=\"toDate\" class=\"desktop dateInput\" onchange=\"yo.NG.doDateSearch();\" onkeypress=\"return false;\" onclick=\"yo.NG.showHideCalendar('toCalendarPicker')\" title=\"End date\"/>\n									<input onpaste=\"return false;\" type=\"date\" name=\"date\" id=\"toDate\" class=\"mobile dateInput\" onclick=\"yo.NG.unresize();\" onkeyup=\"yo.NG.unresize();\" onchange=\"yo.NG.doDateSearch();yo.NG.unresize();\" title=\"End date\"/>\n									<div id=\"toCalendarPicker\" class=\"calendarPicker\"></div>\n								</div>\n							</div>\n						\n								\n							<div id=\"amountFilterDropdown\">\n								<div class=\"errorMsg\">The From amount must be less than the To amount.</div>\n								<div class=\"from\"> \n									<span class=\"lbl\">";
  stack1 = "From";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</span>\n									<input onpaste=\"return false;\" id=\"fromAmount\" maxlength=\"15\" class=\"desktop numberInput\" onkeypress=\"yo.NG.numbersOnly(event);\" onkeyup=\"yo.NG.doAmountSearch(event);\" title=\"From amount\"/>\n									<input onpaste=\"return false;\" type=\"number\" maxlength=\"15\" step=\"any\" id=\"fromAmount\" class=\"mobile numberInput\" onclick=\"yo.NG.unresize();\" onkeyup=\"yo.NG.doAmountSearchWrapperForAndroid();yo.NG.unresize();\" onkeypress=\"yo.NG.numbersOnly(event); setTimeout(function(){yo.NG.doAmountSearch(event);yo.NG.unresize();},100);\" title=\"From amount\"/>\n								</div>\n								<div class=\"to\"> \n									<span class=\"lbl\">";
  stack1 = "To";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</span>\n									<input onpaste=\"return false;\" id=\"toAmount\" maxlength=\"15\" class=\"desktop numberInput\" onkeypress=\"yo.NG.numbersOnly(event);\" onkeyup=\"yo.NG.doAmountSearch(event);\" title=\"To amount\"/>\n									<input onpaste=\"return false;\" type=\"number\" maxlength=\"15\" step=\"any\" id=\"toAmount\" class=\"mobile numberInput\" onclick=\"yo.NG.unresize();\" onkeyup=\"yo.NG.doAmountSearchWrapperForAndroid();yo.NG.unresize();\" onkeypress=\"yo.NG.numbersOnly(event); setTimeout(function(){yo.NG.doAmountSearch(event);yo.NG.unresize();},100);\" title=\"To amount\"/>\n								</div>\n							</div>\n							<ul id=\"categoryFilterDropdown\" class=\"filter-dropdown f-dropdown custom-dropdown\"></ul>\n							\n						</div>\n					</div>\n					\n				</div>\n			</div>\n		";
  return buffer;}

  buffer += "<div id=\"toolbar-js\">\n	";
  stack1 = "showTasks";
  stack2 = "||";
  stack3 = "showAddAnAccountLink";
  foundHelper = helpers.ifCond;
  stack4 = foundHelper || depth0.ifCond;
  tmp1 = self.program(1, program1, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  if(foundHelper && typeof stack4 === functionType) { stack1 = stack4.call(depth0, stack3, stack2, stack1, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack4, stack3, stack2, stack1, tmp1); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n	\n	<div class=\"general-overlay hide\" id=\"accounts-overlay\">&nbsp;</div>\n	\n	<div id=\"searchResultsContainer\" onclick=\"yo.NG.blurFilters(event);\" tabindex=\"0\" role=\"dialog\">\n				\n		<div id=\"desktopSearchCancel\" class=\"desktop\" onclick=\"yo.NG.hideSearchContainers();\" onkeyup=\"if(yo.enter(event)){yo.NG.hideSearchContainers();}\" role=\"button\" title=\"Close search\" tabindex=\"0\">\n			<span class=\"cancelIcon\">\n				";
  foundHelper = helpers.cancelIcon;
  stack1 = foundHelper || depth0.cancelIcon;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "cancelIcon", { hash: {} }); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n			</span>\n		</div>\n		\n		<div id=\"mobileSearchCancel\" onclick=\"yo.NG.hideSearchContainers();\" role=\"button\" title=\"Close search\" tabindex=\"0\">\n			<span class=\"cancelIcon\">\n				";
  foundHelper = helpers.cancelIcon;
  stack1 = foundHelper || depth0.cancelIcon;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "cancelIcon", { hash: {} }); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n			</span>\n		</div>\n		\n		";
  stack1 = "true";
  stack2 = "==";
  stack3 = "showSearch";
  foundHelper = helpers.ifCond;
  stack4 = foundHelper || depth0.ifCond;
  tmp1 = self.program(11, program11, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  if(foundHelper && typeof stack4 === functionType) { stack1 = stack4.call(depth0, stack3, stack2, stack1, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack4, stack3, stack2, stack1, tmp1); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n		<div id=\"currentFiltersDisplay\" class=\"center\">\n			<div id=\"currentDateFilter\" class=\"currentFilter\">\n				<span class=\"currentFilterValue\">\n					<span class=\"from\"></span>&nbsp;&ndash;&nbsp;\n					<span class=\"to\"></span>\n				</span>\n				<span class=\"clearSearchIcon\" onclick=\"yo.NG.clearDateSearch(true)\">x</span>\n			</div>\n			<div id=\"currentAmountFilter\" class=\"currentFilter\">\n				<span class=\"currentFilterValue\">\n					<span class=\"from\"></span>&nbsp;&ndash;&nbsp;\n					<span class=\"to\"></span>\n				</span>\n				<span class=\"clearSearchIcon\" onclick=\"yo.NG.clearAmountSearch(true)\">x</span>\n			</div>\n			<div id=\"currentCategoryFilter\" class=\"currentFilter\">\n				<span class=\"currentFilterValue\"></span>\n				<span class=\"clearSearchIcon\" onclick=\"yo.NG.clearCategorySearch(true)\">x</span>\n			</div>\n		</div>\n		\n		<div id=\"searchResultsPrimary\"> <!-- this will hide when we display the tags transactions list -->\n			<div class=\"searchResultsWrapper\">\n				<div id=\"tagsSearchResultsContainerHeaderWrapper\">\n				</div>	\n				<div id=\"tagsSearchResults\">\n				</div>\n			</div>\n			<div class=\"searchResultsWrapper\" id=\"txSearchResultsWrapper\">\n				<div id=\"searchResultsContainerHeaderWrapper\">\n				</div>	\n				<div id=\"searchResults\">\n				</div>\n				\n				<div id=\"showMoreTxn\">";
  stack1 = "See More..";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\n				</div>\n			</div>\n		</div>\n		\n		<div id=\"searchResultsSecondary\">\n			<div id=\"selectedTagNameHeader\">\n				<span class=\"tagHeaderIcon\">\n					";
  foundHelper = helpers.tagHeaderIcon;
  stack1 = foundHelper || depth0.tagHeaderIcon;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tagHeaderIcon", { hash: {} }); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n				</span>\n				<span id=\"selectedTagName\"></span>\n			</div>\n		</div>		\n		<span focusable=\"true\" tabindex=\"0\" onkeydown=\"yo.rotateDialogFocus(this.parentNode,event);\" onblur=\"yo.rotateDialogFocus(this.parentNode,event);\" class=\"ada-offscreen\">";
  stack1 = "End of dialog content";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</span>\n	</div>\n	\n	<div class=\"options-bar border-bottom\" style=\"border-top-width: 0px;\">\n		\n		<div id=\"primaryNav\">\n			<ul id=\"navul\">\n				<li>\n					<a tabindex=\"0\" role=\"button\" class=\"default past\" href=\"#\" onclick=\"yo.NG.switchView('past');\" onkeyup=\"if(yo.enter(event)){yo.NG.switchView('past');}\" title=\"";
  stack1 = "PAST";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + ". ";
  stack1 = "Go to past financial details";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\" class=\"btn-text\">\n						<div class=\"time-menu-label animateFast\">";
  stack1 = "PAST";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + " <span class=\"ada-offscreen\">";
  stack1 = "Go to past financial details";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</span></div>\n						<div class=\"selector\"></div>\n					</a>\n				</li>\n				<li>\n					<a tabindex=\"0\" role=\"button\" class=\"selected now\" href=\"#\" onclick=\"yo.NG.switchView('now');\" onkeyup=\"if(yo.enter(event)){yo.NG.switchView('now');}\" title=\"";
  stack1 = "NOW";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + ". ";
  stack1 = "Go to current financial details";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\" class=\"btn-text\">\n						<div class=\"time-menu-label default animateFast\">";
  stack1 = "NOW";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + " <span class=\"ada-offscreen\">";
  stack1 = "Go to current financial details";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</span></div>\n						<div class=\"selector\"></div>\n					</a>\n				</li>\n				<li>\n					<a tabindex=\"0\" role=\"button\" class=\"default future\" href=\"#\" onclick=\"yo.NG.switchView('future');\" onkeyup=\"if(yo.enter(event)){yo.NG.switchView('future');}\" title=\"";
  stack1 = "FUTURE";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + ". ";
  stack1 = "Go to future financial details";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\" class=\"btn-text\">\n						<div class=\"time-menu-label animateFast\">";
  stack1 = "FUTURE";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + " <span class=\"ada-offscreen\">";
  stack1 = "Go to future financial details";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</span></div>\n						<div class=\"selector future\"></div>\n					</a>\n				</li>\n			</ul>\n		</div>	\n		\n	</div>\n</div>\n<div id=\"body-content-js\" class=\"body-content\" style=\"overflow:visible\">\n	<div class=\"hide empty\">\n        <p>";
  stack1 = "There is no data to display";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</p>\n        <p class=\"no-filters-message\">";
  stack1 = "details?";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</p>\n    </div>\n	<div class=\"row-fluid chart show-combo load-hidden\">\n		<div id=\"now\">\n			<div class=\"graphDiv\">\n				<div id=\"toggleContainer\">\n			        <div class=\"toggleButton sel\" onclick=\"yo.NG.toggleTheButton(this)\">";
  stack1 = "CHECKING";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</div>\n			        <div class=\"toggleButton\" onclick=\"yo.NG.toggleTheButton(this)\">";
  stack1 = "CREDIT";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</div>\n			    </div>\n				<div id=\"centerCircle\"></div>\n				<div id=\"trendGraph\" class=\"graph\" aria-hidden=\"true\">\n				</div>\n				<div id=\"nav-left\" class=\"stretch\">\n					<div id=\"chartMinus\" tabindex=\"0\" role=\"button\" class=\"navChevron\" onclick=\"yo.NG.switchView('past');\" onkeyup=\"if(yo.enter(event)){yo.NG.switchView('past');}\" style=\"visibility: visible;\">";
  foundHelper = helpers.bigLeftArrow;
  stack1 = foundHelper || depth0.bigLeftArrow;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "bigLeftArrow", { hash: {} }); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "</div>\n				</div>\n				<div id=\"nav-right\" class=\"stretch\">\n					<div id=\"chartPlus\" tabindex=\"0\" role=\"button\" class=\"navChevron right\" onclick=\"yo.NG.switchView('future');\" onkeyup=\"if(yo.enter(event)){yo.NG.switchView('future');}\" style=\"visibility: visible;\">";
  foundHelper = helpers.bigRightArrow;
  stack1 = foundHelper || depth0.bigRightArrow;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "bigRightArrow", { hash: {} }); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "</div>\n				</div>\n			</div>\n			<div id=\"accounts\">\n			</div>\n			<div id = \"nowInprogressTransactions\"></div>\n		</div>\n		<div id=\"past\">\n			<div id=\"postedTransactions\">\n			</div>\n		</div>\n		<div id=\"future\">\n			<div id=\"scheduledTransactions\">\n			</div>\n			<div id=\"bills\">\n			</div>\n		</div>\n	</div>\n</div>";
  return buffer;});
return templates;
});
/**
 * this view is responsible for showing single account settings, controls and apis to change account settings
 */
define('10003204_js/views/UserNotificationsView',['10003204_js/models/UserNotificationModel','10003204_js/compiled/finappCompiled'],function(UserNotificationModel,templates){
    var UserNotificationsView = Backbone.Marionette.ItemView.extend({
            
    	//region: '#accounts',
    	self:this,
    	
    	template: templates['UserNotifications'],
    	
    	initialize : function(options) {
    		//this.containerType = options.containerType;
    	},
    	events :{
    		
    	},
    	
    	onRender: function(){
        this.$('.leftArrow').html( ((yo.IE==8)?'<i class="i-z0019up_arrow"></i>':params.svg.leftArrowWhite));
    	},
    	templateHelpers : {

              showPushSettings: function() {
                return PARAM.isMobile && yo.device == 'Android'; // returns TRUE = enabled for downloadable android only!
              },
              acctName: function(){
                return this.name ? this.name : '';
              },
              fiName: function(){
                return this.siteName ? this.siteName : false;
              },
              amount0 :function(){  //this is because we are using money helper in template, hence we get access to yo.self
              	return yo.self.amount[0];
              },
              amount1 :function(){
              	return yo.self.amount[1];
              },
              acctId :function(){
              	return this.id;
              },
              acctHeldAway: function() {
                return !yo.truth(this.isHeld); // return FALSE is HeldAway account
              },
              acctContainerType: { // valid container types: Bank, Bills, Credit, Rewards
                'BANK'    : function () {return this.type.match(/^(BANK|Banking)$/) ? true : false},
                'BILLS'   : function () {return this.type.match(/^(BILLS|CABLE_SATELLITE|TELEPHONE|Cable &amp; Satellite|Phone &amp; Long Distance)$/) ? true : false},
                'CREDIT'  : function () {return this.type.match(/^(CREDITS|Credit Cards)$/) ? true : false},
                'REWARDS' : function () {return this.type.match(/^(REWARD_PROGRAM|MILES|Rewards|Miles)$/) ? true : false},
              }
       },
       
       close : function(){
       		//release the dom and memory
       		this.remove();
       }
    });
    return UserNotificationsView;
});



define('10003204_js/views/TimelyView',['10003204_js/collections/TimelyCollection','10003204_js/models/UserNotificationModel', '10003204_js/views/UserNotificationsView', '10003204_js/compiled/finappCompiled'],function(TimelyCollection,UserNotificationModel,UserNotificationsView,templates){
    var TimelyView = Backbone.Marionette.ItemView.extend({
                
		region: yo.timelyRegion || '#main-container',
		
		events: {
		    'keypress #searchinput' : 'gohere',
		},
		template: templates['main'],
		
		gohere: function(){
		    Application.Mediator.trigger('SEARCH_TXN', 'keyword');
		},
		renderUI: function() {
		   // if accounts exists show them as per the template
		   
		   yo.showNotifications = function(event){
				//event.stopPropagation();
				
	            
				// create account data model
           	    var userNotificationModel = new UserNotificationModel();
           	    
           	    //create account settings view
           	    var userNotificationsView = new UserNotificationsView({model:userNotificationModel});
				yo.NG.showSearch();
				$('#searchBoxContainer').hide();
				$('#advancedSearch').hide();
				$('#searchResults').html(userNotificationsView.render().el);
				yo.activeContainer="searchResultsContainer";
				$('#searchResultsContainer').addClass('accountsOverlay');
				Foundation.libs.reveal.close(); //all Foundation methods can be called globally hooray!
				//yo.resize();
			};
		   if(this.collection) {
		        
		        yo.NG.Data = this.collection.models;
		        this.setPageWidths();
		        if(!yo.accountType)//TODO get account type from top account we are rendering but for now hard coding to bank
		        yo.accountType='bank'; 
				this.renderChart(yo.NG.Data);
				
				if(yo.width<=320){
					//we are in mobile land
					
					var div = $("#centerCircle");
					div.prepend('<canvas id="circleCanvas" width="250" height="250"></canvas>');
					var c = document.getElementById("circleCanvas");
					var ctx = c.getContext("2d");
					
					var grd = ctx.createLinearGradient(0,0,0,200);
					grd.addColorStop(0,"#67C0CA");
					grd.addColorStop(1,"#AFC3C0");
					
					ctx.beginPath();
					ctx.arc(100,120,100,0,2*Math.PI);
					ctx.fillStyle = grd;
					ctx.fill();
					
				}
				
				this.formatPage();
				
				if(params.moduleSwitch.accountsModule=="on"){
					Application.Appcore.loadModule({ moduleKey : '10003204_10003403', moduleId : '10003403', el:'#accounts', region :'#accounts', divId:'#accounts'});
				}
				if(params.moduleSwitch.transModule=="on"){
					Application.Appcore.loadModule({ moduleKey : '10003204_10003507', moduleId : '10003507', el:'#nowInprogressTransactions', region :'#nowInprogressTransactions', divId:'#nowInprogressTransactions'});
				}
				yo.activeContainer='now';
				
				yo.uiLoad.end();
				
				yo.NG.renderPast();
				yo.NG.renderFuture();
				
				if(params.moduleSwitch.userSettingsModule=="off"){
					//hide user settings
					var actnBtn = $('.btn-link.account');
					actnBtn.addClass("hide");
				}
				
				var hammernow = new Hammer($('#now')[0]);//add guestures
				hammernow.on('panleft', function(ev) {
				    if(!yo.lockSwipes&&Math.abs(ev.deltaX)>100){
				    	yo.NG.switchView('future');
				    }
				});
				hammernow.on('panright', function(ev) {
				    if(!yo.lockSwipes&&Math.abs(ev.deltaX)>100){
				    	yo.NG.switchView('past');
				    }
				});
				
				var hammerpast = new Hammer($('#past')[0]);//add guestures
				hammerpast.on('panleft', function(ev) {
				    if(!yo.lockSwipes&&Math.abs(ev.deltaX)>100){
				    	yo.NG.switchView('now');
				    }
				});
				
				var hammerfuture = new Hammer($('#future')[0]);//add guestures
				hammerfuture.on('panright', function(ev) {
				    if(!yo.lockSwipes&&Math.abs(ev.deltaX)>100){
				    	yo.NG.switchView('now');
				    }
				});
		        
			    return this;
		   }else { // if 0 accounts; show add account 	
		        document.body.innerHTML+=this.noDataTemplate();
		   }
		},
		
		/**renders no Data template when theree is no data**/
		renderNoData: function() {
		   // if trends don't exist show them no data template
		   
		   document.body.innerHTML+=this.noDataTemplate();
		   
		},
		
		/**noData Template to load as our view if there are no accounts*/
		noDataTemplate :function(){
			var content = [];
			content.push('<div class="no-accts-container">\
				<h3> '+__["You haven\'t added any accounts yet."]+' </h3>\
				<div class="accts-type">\
					<div class="span1">\
						<span class="i-lge-bank"></span>\
					</div>\
					<div class="span1">\
						<span class="i-lge-chart"></span>\
					</div>\
					<div class="span1">\
						<span class="i-lge-mortgage"></span>\
					</div>\
				</div>\
				<p> '+__["Add accounts so you can see how your assets and liabilities are working together and give yourself a picture of your net worth and how your investments are performing."]+' </p>\
				<div class="footer-actions">\
					<a href="#" data-js="message" data-message="invokeAddAccountLink" title="'+__['Add Account']+__[' - Opens a simulated dialog']+'" class="btn btn-large btn-primary pull-left">'+__["Add Account"]+'</a>\
				</div>\
			</div>\
			<script type="text/javascript">\
				PARAM.noAccounts = true;\
			</script>');
			return content.join('');
		},
		
		/***
		 * rendersHighcharts chart
		 * @param {Object} data json Model data passed to chart to render 
		 */

		renderChart: function(data) {
			
			var i;
			try {
				var chartData = data
				var amounts = [],
					iLen = 0;
				
				if(chartData && chartData.length > 0){
					iLen = chartData.length
					
					$('body').removeClass('no-data');
					$('.empty').addClass('hide');
					$('.chart').removeClass('hide')
				} else {
					throw new Error('No Data')
				} 
				
			} catch (error) {
				
				// Show no data message
				$('body').addClass('no-data')
				$('.empty').removeClass('hide')
				$('.chart').addClass('hide')
				return;
			}
			
			
			for (i=0; i<iLen; i++) {
				
				if(chartData[i].attributes.bill){
					var number = chartData[i].attributes.bill.amount[0].toString().replace(/\$|\,/g,'')
				}else{
					var number = chartData[i].attributes.amount[0].toString().replace(/\$|\,/g,'')
				}
				
				if (!isNaN(number)){
					if(chartData[i].bill){	
        				dataEntry = parseFloat(chartData[i].attributes.bill.amount[0])
        			}else{
        				dataEntry = parseFloat(chartData[i].attributes.amount[0])
        			}
        		}else{
        			dataEntry = 0.0
        		}
        		if(chartData[i].attributes.bill){	
        			//Bug : 526111 bills are sorted by the db in reverse order apparently for some reason
        			var billDue = parseInt(Date.fromISOString(chartData[i].attributes.bill.date).getTime());
        			if(amounts.length>0 && billDue < amounts[0][0]){
        				amounts.unshift([billDue, dataEntry])
        			}else{
        				amounts.push([billDue, dataEntry])
        			}
				}else{
					amounts.push([parseInt(chartData[i].attributes.time), dataEntry])
				}
			}

			// Handle Range Issues
			var xRange = amounts[(amounts.length - 1)][0] - amounts[0][0],
				MONTH = 1000 * 60 * 60 * 24 * 31,
				WEEK = 1000 * 60 * 60 * 24 * 7;
			var showTable = $('.show-table');//bug: 540097
			if(showTable){
				showTable.removeClass('show-table');
				showTable.addClass('show-chart');
			}
			var chartMarginRight; 
			if(yo.width>1500){
				chartMarginRight = yo.width*0.05;//large
			}else if(yo.width>1100){
				chartMarginRight = yo.width*0.06;//large
			}else if(yo.width>900){
				chartMarginRight = yo.width*0.08;//large
			}else if(yo.width>750){
				chartMarginRight = yo.width*0.10;//medium
			}else if(yo.width>600){
				chartMarginRight = yo.width*0.11;//medium
			}else if(yo.width>500){
				chartMarginRight = yo.width*0.15;//medium
			}else if(yo.width>400){
				chartMarginRight = yo.width*0.18;//medium
			}else{
				chartMarginRight = yo.width*0.20;//small
			}
			
			yo.NG.linechart =new Highcharts.Chart({
	
				chart: {
	        		renderTo: 'trendGraph',
	        		type: 'spline',
	        		zoomType: 'x',
	        		marginRight: chartMarginRight,
	        	    animation: false,
	        	    marginTop: 30,	      
	        	    spacingTop: 0,
	        	    height:250
	    		},
	    		title : {
	    			text: null
	    		},
	    		legend: {
	        		enabled:false
	    		},
	    		xAxis: {
	    			type: 'datetime',
	    			startOnTick: false,
	    			minRange: (2 * WEEK),
	    			minPadding: 0,
	    			maxPadding: 0,
	    			lineColor:PARAM.gridLineColor,
	                labels: {
	                	style:{
		    				color:PARAM.chartLabelColor,
		    				fontSize:PARAM.chartLabelSize,
		    				fontFamily:PARAM.chartLabelFont
		    			},
	    				formatter: function() {
	    					return Highcharts.dateFormat('%b', this.value).toUpperCase() + " " + Highcharts.dateFormat('%d', this.value) +'<br>' + Highcharts.dateFormat('%Y', this.value)
	   					}
					},
					tickLength: 0,
					lineWidth: 2,
					
	        	},
	        	yAxis: {
	        		minTickInterval: 10,
	        		minRange: 100,
	        		lineColor:PARAM.gridLineColor,
	        		labels: {
	        			style:{
		    				color:PARAM.chartLabelColor,
		    				fontSize:PARAM.chartLabelSize,
		    				fontFamily:PARAM.chartLabelFont
		    			},
	            		formatter: function() {

                			var value = Math.floor(this.value),
                				lookup = [[1000,'K'],[1000000,'M'],[1000000000,'B'],[1000000000000,'T'],[1000000000000000,'Q']],
                				len = Math.abs(value).toString().length,
                				key = (Math.floor((len - 1) / 3)) - 1,
                				map = (key >= 0 && key <= 4) ? lookup[key] : [1,''],
                				SIPrefix = map[1];

                			// Format Value
                			var posOrNeg = (value < 0) ? "-" : "",
                				value = value/map[0],
                				value = Math.abs(value),
                				value = ((value % 1).toString().length > 2) ? (Math.round(value*100)/100) : value;

                			// Currency Formatting
                			// Some cobrand envs. dont have prefs for notation. Ex. BAC ... Also setting default to SYMBOL in case same is true for others
                			if(chartData[0].attributes.bill){
								var currencyCode = chartData[0].attributes.bill.amount[1]
	            			}else{
	            				var currencyCode = chartData[0].attributes.amount[1]
	            			}
                			var currencyPrefs = yo.getFormatPreferencesByCurrency(currencyCode),
                				currencyText = currencyPrefs.txt,
                				currencySymbol = currencyPrefs.symbol,
                				currencyNotation = PARAM.prefs.currencyNotation ? PARAM.prefs.currencyNotation : 'SYMBOL',
                				notationLookup = {'TEXT':currencyCode, 'TEXTSYMBOL':(currencyText + currencySymbol), 'SYMBOL':currencySymbol},
                				currencyNotated = notationLookup[currencyNotation],
                				spaceAfterSymbol = currencyPrefs.spaceAfterSymbol ? " " : "";
             
                			//Localization
                			var userLocale = PARAM.prefs.locale,
                				isFrench = (userLocale == "fr_CA" || userLocale == "fr_FR") ? true : false;

                			// Return 
                			var formatted = (isFrench) ? (posOrNeg + value + SIPrefix + currencyNotated) : (posOrNeg + currencyNotated + spaceAfterSymbol + value + SIPrefix);	

                			return formatted
                		}
	        		},
	        		plotLines: [{
	        			width: 2,
	        			value: 0,
	        			zIndex: 4
	        		}],
	        		title: {
	        			text: null
	        		},
	        		gridLineColor: "transparent",
	        		maxPadding: 0,
	        		startOnTick: true,
	        		minPadding: 0.02,
	        		lineWidth: 2,
	        		zIndex: 4
	    		},
	    		plotOptions: {     
	                spline: {
	                	marker:{
	                		lineColor: PARAM.markerLineColor,
	                		radius:4,
	                	},
	                	lineWidth: 2,
	                	shadow: false,
	                	events: {
	                		legendItemClick: function () {
	                			return false;
	                		}
	                	},
	                	halo:{
	                		opacity:0.2,
	                		size:1
	                	}
	                },
	                series: {
	                	animation: false,
	                	fillOpacity: 0.5
	                }
	        	},
	    		tooltip: {
	            	shared: true,
	            	crosshairs: false,
	            	useHTML: true,
	            	xDateFormat: '%B %d,%Y',
	            	formatter: function () {
						if(chartData[0].attributes.bill){
							var curr = chartData[0].attributes.bill.amount[1]
            			}else{
            				var curr = chartData[0].attributes.amount[1]
            			}
            			var paths = $(".highcharts-tooltip")[0].getElementsByTagName("path");
            			if(paths.length==0){
            				paths = $(".highcharts-tooltip")[0].getElementsByTagName("shape");//ie8 support
            				$(paths[paths.length-2]).attr({'height': paths[paths.length-2].clientHeight-10,'width':paths[paths.length-2].clientWidth-10});
            				$(paths[paths.length-1]).attr({'display': 'none',});//the fill was rgba(249, 249, 249, .85) and the border was 1px white
            			}else{
            				//$(paths[paths.length-2]).attr({'height': paths[paths.length-2].height-10,'width':paths[paths.length-2].width-10});
            				$(paths[paths.length-1]).attr({'fill': 'rgba(249, 249, 249, .50)','stroke-width':0});//the fill was rgba(249, 249, 249, .85) and the border was 1px white
            			}
            			
                		var formatted = "";
                		
                		formatted+='<div class="now" style="display: block; opacity: 1;">'+
                			'<div class="closeBar" style="margin-top: 0px; width: 200px; opacity: 1; transform: matrix(1, 0, 0, 1, 0, 0);background:rgba(249, 249, 249, .85);">'+
                		 		'<div class="copy" style="opacity: 1;">'+
                		 			'<div class="title">';
                		var datePref = PARAM.prefs.dateFormat.toUpperCase()
                		switch (datePref) {
                			case 'DD/MM/YYYY':
                			case 'DD.MM.YYYY':
                				formatted += Highcharts.dateFormat('%e', this.points[0].x) + " " + Highcharts.dateFormat('%B', this.points[0].x).toUpperCase() + ", " + Highcharts.dateFormat('%Y', this.points[0].x)
								break;
                			case 'MM/DD/YYYY':
                				formatted += Highcharts.dateFormat('%B', this.points[0].x).toUpperCase() + ' '+ Highcharts.dateFormat('%e', this.points[0].x) + ", " + Highcharts.dateFormat('%Y', this.points[0].x)
                				break;
                			case 'YYYY-MM-DD':
                				formatted += Highcharts.dateFormat('%Y', this.points[0].x) + " " + Highcharts.dateFormat('%B', this.points[0].x).toUpperCase() + ", " + Highcharts.dateFormat('%e', this.points[0].x)
                				break;
                			default:
                		}
                		formatted+= '</div>'+
                		 			'<p>'+yo.money(this.points[0].y, curr, true)+'</p>'+
                		 		'</div>'+
                		 	'</div>'+
                		 	'<div class="details" style="background:rgba(249, 249, 249, .85);">'+
                		 		'<div class="item" style="opacity: 1;">'+
                		 			'<p>DARWIN CAFE</p>'+
                		 			'<p class="right">-$10.50</p>'+
                		 		'</div>'+
                		 		'<div class="item" style="opacity: 1;">'+
                		 			'<p>STARBUCKS</p>'+
                		 			'<p class="right">-$9.17</p>'+
                		 		'</div>'+
                		 	'</div>'+
                		 	'<div class="post"></div>'+
                		 '</div>';

                		return formatted
                	},
	            	pointFormat: '{series.name}: ${point.y}<br>',
	            	style: {
						fontSize: '10px',
						padding: '0px'
					}
	    		},
	    		series: [{
	    			//name: $('.chart .table').data('column-label-account-balance'),
	    			name: yo.NG.returnCorrectLabel(),
	    			data: amounts,
	    			type: "spline",
	    			color: PARAM.chartLineColor,
	    			zIndex: 1
	    		}]
			});
			
			if(showTable){
				showTable.addClass('show-table');
				showTable.removeClass('show-chart');
			}
	
		}
		
		/**needed because they need to be set to the body's width and this needs to change when tilted on a tablet or phone*/
		
		,setPageWidths :function(){
			yo.width = document.body.clientWidth;
			$('#past').css('width',yo.width);
			$('#now').css('width',yo.width);
			$('#future').css('width',yo.width);
		}
		
		/**
		 *
		 * Calculates top and bottom colors to use in gradient based on data for time period using the PARAM.colorMatrix provided by UX/PS
		 *  
		 **/
		
		,calcColorLimits: function(){
			
			var res = yo.NG.Data,
			i,j,high,low,lastStop;
			for(i=0;i<res.length;i++){
				if(i==0){
					high=parseFloat(res[i].attributes.amount[0]);
					low=parseFloat(res[i].attributes.amount[0]);
				}else{
					var newnum=parseFloat(res[i].attributes.amount[0]);
					if(newnum>high){
						high = newnum;
					}
					if(newnum<low){
						low = newnum;
					}
				}
			}
			//got highest and lowest amount from data now, use it to figure out spots in spread calc
			
			//PARAM.colorStops.high
			var max = PARAM.comfortableBalance*2;//anything two times the comfortable balance is 100% or greater comfort zone
			//var min = PARAM.comfortableBalance/2;//anything half the comfortable balance or less is in the red/orange (whatever color) zone
			
			var highPercentOfMax = high/max;
			var lowPercentOfMax = low/max;
			var maxValToUse = parseInt((highPercentOfMax*100).toFixed(0));
			var minValToUse = parseInt((lowPercentOfMax*100).toFixed(0));
			
			PARAM.colorMatrix = [];
			var colorStops = PARAM.colorStops.split(',');
			 //colorStops now looks like this: [003b72:93],[1a4c84:87]etc..
			 
			i=0;lastStop=100;
			for(j=100;j>=0;j--){
				
				PARAM.colorMatrix[j] = colorStops[i].split(':')[0];
				
				if(j==colorStops[i].split(':')[1]){
					i++;
					if(lastStop>maxValToUse&&j<maxValToUse){
						maxValToUse = lastStop;
					}
					lastStop = j;
					
				}
				if(i>colorStops.length)break;
			}
			//creates an array like this: {100:003b72,...,93:003b72,92:1a4c84etc..}
			
			return ['#'+PARAM.colorMatrix[maxValToUse],'#'+PARAM.colorMatrix[minValToUse]];
		}
		
		/**
		 *  Our Standard formatPage function, calls calculate and set gradient on the chart and loads Accounts Module and pending Transactions Module 
		 */
		,formatPage: function(){
			var dates = $('.date');
			for(i=0;i<dates.length;i++){
				dates[i].innerHTML = moment(dates[i].innerHTML).fromNow();
			}
			
			var limits= this.calcColorLimits('now')
			,graphDiv = $('.graphDiv');
			if(yo.IE<10&&yo.IE!=-1){
				graphDiv[0].style.filter="progid:DXImageTransform.Microsoft.gradient(startColorStr='"+limits[0].toUpperCase() +"', endColorstr='"+limits[1].toUpperCase()+"')";
			}else if(yo.IE==10){
				graphDiv.css('background','-ms-linear-gradient('+limits[0] +','+limits[1]+')');
			}else{
				graphDiv.css('background','linear-gradient('+limits[0] +','+limits[1]+')');
			}
			
			
			
			
			setTimeout(function(){
				yo.resize();
				$('.highcharts-background').remove(); //removes all matched elements from the DOM
			},100)
		
			$(document).foundation({	
				
				dropdown: {
					activeClass: 'open',
  					is_hover: false,
					opened: function(){
						if($(".custom-dropdown.open").length) {
							var dropId = $(".custom-dropdown.open").attr("id");
							var btnId = dropId.slice(0, -5);
							$("#" + btnId + " .chevron").html(((yo.IE==8)?'<i class="i-z0019up_arrow"></i>':params.svg.upArrow));
			            	$("#" + dropId).width($("#" + btnId).innerWidth() );
						
						}
					},
					closed: function(){
	        			$(".dropdown .chevron").html(((yo.IE==8)?'<i class="i-z0012down_arrow"></i>':params.svg.downArrow));
	        			//$("#searchBox").hide();
	        			//$("#searchLink").show();
					}
				},
				reveal: {
				  opened: function(){
				  	if($(".toolTip.open").length) {
					    yo.positionTooltip();		  		
				  	}
				  	else if($("#taskmenu.open").length) {
						yo.NG.positionTasks();
				  	}
				  },
				  closed: function(){ 
				    $("#tooltip-triangle").hide();
				  },
				  animation: 'null'
				}
			});
			
			var bell = $('.bell')[0];
			if (bell) {
				bell.innerHTML = params.svg.bell + ' '+ bell.innerHTML;
			}
			
		},
		
		templateHelpers : {
			switchEnableNotificationSettings: function () {
				return yo.truth(params.switchEnableNotificationSettings);
			},
			cancelIcon: function(){
	            return params.svg.cancelIcon; // this refers to the model//if there is no extra helper, just use this, otherwise use yo.self
	    	},
	    	bankLogo:function(){
	       		return params.svg.bankLogo;
	    	},
	    	acctsIcon:function(){
	       		return params.svg.acctsIcon+'<i class="i-z0025profile"></i>';
	    	},
	    	crossHairsIcon:function(){
	       		return params.svg.crossHairsIcon+'<i class="i-z0024plus"></i>';
	    	},
	    	searchIcon:function(){
	    		return params.svg.searchIcon+'<i class="i-z0015search"></i>';
	    	},
	    	smallDownAndUpArrow:function(){
	    		return params.svg.smallDownAndUpArrow+'<i class="i-z0012down_arrow"></i><i class="i-z0019up_arrow"></i>';
	    	},
	    	tagIcon:function(){
	    		return params.svg.tagIcon+'<i class="i-z0017tag"></i>';
	    	},
	    	tagHeaderIcon:function(){
	    		return params.svg.tagHeaderIcon+'<i class="i-z0017tag"></i>';
	    	},
	    	bigLeftArrow:function(){
	    		return params.svg.bigLeftArrow+'<i class="i-z0020left_arrow"></i>';
	    	},
	    	bigRightArrow:function(){
	    		return params.svg.bigRightArrow+'<i class="i-z0021right_arrow"></i>';
	    	}
		}
		
    });
    return TimelyView;  
});



define('10003204_js/controllers/TimelyController',['10003204_js/views/TimelyView','10003204_js/collections/TimelyCollection'], function(TimelyView,TimelyCollection) {
	var TimelyController = Backbone.Marionette.Controller.extend({
		initialize: function() {
			//console.log('Container Controller is initialized.');
  		},

		start: function(options) {
			var renderFuncs = function(){
				var dataObj = {obj:PARAM.trendsData.obj};
				if( PARAM.trendsData && PARAM.trendsData.obj) {
	    		  self.collection = new TimelyCollection(PARAM.trendsData.obj.results? PARAM.trendsData.obj.results: [] );
	    		} 
	    		self.tView = new TimelyView({ collection: self.collection, moduleKey : options.moduleKey, el:'#main-container'});
	    		
		      	self.tView.render();
	    		self.tView.renderUI();
	    		yo.NG.initFilter(dataObj);
			};
			if( !PARAM.trendsData || !PARAM.trendsData.obj.results ) {
				yo.api('/services/DataPoint/all/', function(data){
					PARAM.trendsData = data;
					renderFuncs();
				});
			}else{
				renderFuncs();
			}
		}
	});
	return TimelyController;
});
define('10003204_js/finapp',['10003204_js/controllers/TimelyController'],function(TimelyController){
	var module = Application.Appcore.Module.extend({

		controller : TimelyController,

		initialize : function(options) {
			this.region = this.getRegion();
		},
		
		getRegion :function(){
			return "#main-container";
		},
	});
	return module;
});
		
Date.fromISOString = (function(){//used for Bills Api in Trend Chart
	//old browsers (ie7 and 8 lack this)
  var tzoffset = (new Date).getTimezoneOffset();
  function fastDateParse(y, m, d, h, i, s, ms){ // this -> tz
    return new Date(y, m - 1, d, h || 0, +(i || 0) - this, s || 0, ms || 0);
  }

  // result function
  return function(isoDateString){
    var tz = isoDateString.substr(10).match(/([\-\+])(\d{1,2}):?(\d{1,2})?/) || 0;
    if (tz)
      tz = tzoffset + (tz[1] == '-' ? -1 : 1) * (tz[3] != null ? +tz[2] * 60 + (+tz[3]) : +tz[2]);
    return fastDateParse.apply(tz || 0, isoDateString.split(/\D/));
  };
})();
/**
 * Main Class Object for Timely container
 */
yo.NG = {
	self : this,
	searchView: null,
	params : [ 'filter[]=retain_type,true' ],
	txnFilter : null
	
	/**initialization function for each module*/
	, initFilter : function(data) {
		
		var filter=0,i,j;
		if(PARAM.accountData&&PARAM.accountData.data&&PARAM.accountData.data.results){
			var res = PARAM.accountData.data.results;
			for(i=0;i<res.length;i++){
				var acct = res[i].accounts;
				for(j=0;j<acct.length;j++){
				
					if(acct[j].id==PARAM.mainAccount){
						filter = acct[j].id;
						yo.accountType = acct[j].type;
					}
				
				}
			}
			
		}else{
			yo.accountType = PARAM.account_type_emb_param;
		}
		
		if(filter==0||filter=='undefined'){//take the first option if none was saved
			for(i in yo.NG.params){
				if(yo.NG.params[i] && typeof(yo.NG.params[i]) == 'string' && yo.NG.params[i].indexOf('account_id')!=-1){
					filter= yo.NG.params[i].substring(yo.NG.params[i].indexOf('account_id')+11);
					if(filter.indexOf('&')!=-1)
					{
						filter = filter.substring(0,filter.indexOf('&'));
					}
					break
				}
			}
		}
		if(filter.toString().indexOf('_')!=-1)
		{
			filter = filter.split('_')[filter.split('_').length-2]+'_'+filter.split('_')[filter.split('_').length-1];
			
		}
		
		//console.log('data is:'+JSON.stringify(data))
		if ( !data || !data.obj ||!data.obj.results) {

			// Show no data message
			$('body').addClass('no-data');
			$('.empty').removeClass('hide');
			$('.chart').addClass('hide');
			yo.NG.Data = null;
			// Remove loader

			return;
		}
		
	}
	
	, checkIfIncluded: function(fileName){
		
		var scripts = document.getElementsByTagName("script");
	    for(var i = 0; i < scripts.length; i++) {
	        if (scripts[i].src.substr(-fileName.length) == fileName){
	            return true;
	        }
	    }
		return false;
	}
	
	, showSearch:function(el){
		if(yo.device=="na"){
			if(!yo.NG.checkIfIncluded("/js/ui/calendar.js")){
				var script = '<script type="text/javascript" charset="utf-8" src="/js/ui/calendar.js"></script>';
				$("head").append(script);
	
				var calConfig = {
					node:$("#fromCalendarPicker"), 
					inputElement:$("#fromDate"),
					format:"m/d/Y"
				}; 
		
				yo.newCalendar(calConfig);
				yo.newCalendar({node:$("#toCalendarPicker"), inputElement:$("#toDate"), format:"m/d/Y"});
			}
		}

		yo.NG.getTxnFilter().set({fromDate:null});//these get preset based on the cal include. so resetting
		yo.NG.getTxnFilter().set({toDate:null});
		
		$("#fromDate").val("");//this was preset by the calendar, clearing it so field is empty when they first pull up the cal search
		
		
		if(yo.device=="iPad" || yo.device=="iPhone" || yo.device=="Android"){
			$("#toDate.mobile").val(moment(new Date()).format("YYYY-MM-DD"));
		}
		
		yo.storedContainerDiv = yo.activeContainer;
		yo.activeContainer='searchResultsContainer';
		$("#searchResultsContainer").addClass("overlay").show();
		
		if(yo.device=="Android"){
			yo.NG.unresize();//sometimes overlay on android doesn't cover the whole screen on repeated clicking on search 
		}
		//yo.addDropdownSearchEvents($("#categoryFilter"),__["CATEGORY"],params.categoryOptions,"yo.NG.doCategorySearch(this)");
		
		setTimeout(function(){
            $("#searchInput").focus();
        }, 10);/*this shouldn't work on mobile. If it does, wrap it in a condition.*/
		
		return false;
	}
	
	, clearSearch:function(){
		$("#searchInput").val("");
		$("#searchInput").focus();
		
		yo.NG.clearSearchContainers();
	}
	, hideSearch:function(){
		$("#searchInput").val("");
	}
	
	, clearAmountSearch:function(rerunSearch){
		
		$("#fromAmount").val("");
		$("#toAmount").val("");
		
		$("#fromAmount.mobile").val("");
		$("#toAmount.mobile").val("");
		
		$("#currentAmountFilter").removeClass("active");
		$("#currentAmountFilter .from").html("");
		$("#currentAmountFilter .to").html("");

		$("#fromAmount").removeClass("error");
		$("#toAmount").removeClass("error");
		$("#amountFilterDropdown .errorMsg").removeClass("active");
			
		this.getTxnFilter().set({fromAmount:null});
		this.getTxnFilter().set({toAmount:null});
	
		if(rerunSearch){
			yo.NG.rerunSearchIfFilterExists();
		}else{
			yo.NG.clearSearchContainers();
		}
		
	}
	
	, clearDateSearch:function(rerunSearch){
		
		$("#fromDate").val("");
		$("#toDate").val("");
		
		$("#fromDate.mobile").val("");
		$("#toDate.mobile").val("");
		
		$("#currentDateFilter").removeClass("active");
		$("#currentDateFilter .from").html("");
		$("#currentDateFilter .to").html("");
		
		$("#fromDate").removeClass("error");
		$("#toDate").removeClass("error");
		$("#dateFilterDropdown .errorMsg").removeClass("active");
			
		yo.NG.showHideCalendar();
		
		this.getTxnFilter().set({fromDate:null});
		this.getTxnFilter().set({toDate:null});
			
		if(rerunSearch){
			yo.NG.rerunSearchIfFilterExists();
		}else{
			yo.NG.clearSearchContainers();
		}
	}
	
	, clearCategorySearch:function(rerunSearch){
		
		$("#currentCategoryFilter").removeClass("active");
		$("#currentCategoryFilter .currentFilterValue").html("");
		$(".filter-dropdown .selectedCategoryIcon").removeClass("active");
		
		this.getTxnFilter().set({categoryId:""});
		
		if(rerunSearch){
			yo.NG.rerunSearchIfFilterExists();
		}else{
			yo.NG.clearSearchContainers();
		}
	}
	
	, hideSearchContainers:function(){
		yo.NG.hideSearch();	
		$("#searchInput").blur();
		$("#closeSearchIcon").hide();
		$("#searchBoxContainer").removeClass("visible").show();
		$('#searchResultsContainer').removeClass('accountsOverlay');
		$("#searchLink").show();
		yo.NG.hideSearchResults();
		//$("#searchResultsContainer").removeClass("overlay");
		$("#searchResults").removeClass("hideChildren");
		$("#appendedSearchResults").removeClass("hideChildren");
		
		$("#appendedSearchResultsContainer").remove();
		$("#selectedTagName").html("");
		$("#selectedTagNameHeader").hide();
		
		$("#searchResultsSecondary").hide();
		$("#searchResultsPrimary").show();
		
		$("#backToSearch").hide();
		$("#advancedSearch").show();
		$("#currentFiltersDisplay").show();
		
		yo.NG.clearDateSearch();
		yo.NG.clearAmountSearch();
		yo.NG.clearCategorySearch();
		
		$(".dropdowns>div.active").removeClass("active");
		$(".filterBox.active").removeClass("active");
		
		yo.lockSwipes=false;
		$("#tagsSearchResultsContainerHeaderWrapper").html("");
		$("#searchResultsContainerHeaderWrapper").html("");
		$("#showMoreTxn").hide();
		yo.activeContainer=yo.storedContainerDiv;
	}
	
	, hideMobileSearch: function(){
		yo.NG.hideSearch();	
		yo.NG.clearSearchContainers();
		$("#searchResultsContainer").hide();
		$("#searchResultsContainer").removeClass("overlay");
		
		$("#searchResults").removeClass("hideChildren");
		$("#appendedSearchResults").removeClass("hideChildren");
		
		$("#mobileSettings").removeClass("hidden");
	}
	
	, clearSearchContainers: function(){
		//clears the search, leaves overlay
		$("#searchResultsContainer").addClass("overlay");
		
		$("#tagsSearchResults").html("");
		$("#searchResults").html("");
		$("#tagsSearchResultsContainerHeaderWrapper").html("");
		$("#searchResultsContainerHeaderWrapper").html("");
		$("#showMoreTxn").hide();
			
	}
	
	, resizeSearchResults: function(){//for iDevices only
		//after keyboard hide, need container at full height
		setTimeout(function(){
			yo.resize();
		}, 100);
			
	}
	
	/*, showAdvancedSearch: function(){
		$("#advancedSearch").show();
	}
	
	, hideAdvancedSearch: function(){
		$("#advancedSearch").hide();
	}
	*/
	, initializeSearchComponent: function(el, e){
		/*
		if(yo.NG.isMobilePhone()){
			yo.NG.hideAdvancedSearch();
		}*/
		
		var len = $(el).val().length; 
		if(len>0){
			if(!e)  e = window.event;
			var keyCode = e.which || e.keyCode;
			if(yo.NG.charIsNotAllowed(keyCode)) return false;
			
			if(!yo.NG.isMobilePhone()){//don't show for mobile
				$("#closeSearchIcon").show();
			}
			
			if(yo.NG.isMobilePhone() && len==1){	
				$("#searchResultsContainer").addClass("overlay").show();	
			}
		}
		if(len<2){
			//TODO: test this when it's actually testable, if search reruns with the ccurrect criteria'
			this.getTxnFilter().set({keyword:""});
			yo.NG.rerunSearchIfFilterExists();
			//yo.NG.clearSearchContainers();
			
		}else if(len>1){
			//TODO: optimize blinking of screen
			$("#searchResultsContainer").removeClass("overlay");
			
			this.getTxnFilter().set({keyword:$(el).val()});
			yo.NG.renderSearch();
			
    	}
    }
	
	, hideSearchResults: function(){
		$("#searchResultsContainer").hide();
		$("#tagsSearchResults").html("");
		$("#searchResults").html("");
		
	}
	
	, showDateFilter: function(el){
		yo.NG.toggleFilter(el, $(el).hasClass("active"), $("#dateFilterDropdown"));
		yo.NG.showHideCalendar();
		
		if($(el).hasClass("active")){//default to today
			//TODO: get format from user pref
			$("#toDate").val(moment().format("MM/DD/YYYY"));
		}
	}
	
	,unresize:function(){
		setTimeout(function(){
			$('#'+yo.activeContainer).height('');
		},0);
	}
	
	, showAmountFilter: function(el){
		yo.NG.toggleFilter(el, $(el).hasClass("active"), $("#amountFilterDropdown"));
		
	}
	
	, showCategoryFilter: function(el){
		if($.trim($("#categoryFilterDropdown").html())==""){
			yo.NG.writeSearchCategories();
		}
		yo.NG.toggleFilter(el, $(el).hasClass("active"), $("#categoryFilterDropdown"));
		
	}
	
	, toggleFilter: function(el, on, dropdown){
		$(".filterBox.active").removeClass("active");//all
		$(".dropdowns>div.active").removeClass("active");//remove all active dropdowns
		yo.closeDropdownSearch();
		if(!on){
			$(el).addClass("active");
			$(dropdown).addClass("active");
		}
	}
	
	, writeSearchCategories: function(){
	
		var html ='<ul class="filter-dropdown f-dropdown custom-dropdown"></ul>';
		
		//old code
		$("#categoryFilterDropdown").html(html);
		
	}
	
	
	, charIsNotAllowed: function(code){
		//these chars should not trigger a search
		if(code == 9 || code == 13
			|| (code>15 && code<21)
			|| code == 27
			|| (code>32 && code<41)
			|| code == 45 || code == 46
			|| (code>90 && code<94)
			|| code==144 || code==145
			){
			return true;
		} 
		return false;
	}
	
	, backtoSearchSVG: function() {
		$('.leftArrowIcon').innerHTML = ((yo.IE==8)?'<i class="i-z0019up_arrow"></i>':params.svg.leftArrowBlue);
    }
        
    , isMobilePhone: function(){
    	if(yo.width<=360){
    		return true;
    	} 
    	if(yo.width<=414 && $("body").hasClass("iphone")){
    		return true;
    	}
    	if(yo.width<=384 && $("body").hasClass("android")){
    		return true;
    	}
    	//TODO: add more conditions for android here
    	return false;
    }   
    
    , isTablet: function(){
    	if(yo.width<=768 && yo.width>320){
    		return true;
    	}
    	return false;
    }  
      
    , isNexusTablet: function(){
    	if(yo.width==604 && $("body").hasClass("android")){
    		return true;
    	} 
    	return false;
    }           
	/**
	 *switches app from past to now to future view (whichever is selcted)
	 * @param {String} view is the view chosen to switch to by clicking on it
	 */
	, switchView :function(view){
		var selected = $('#primaryNav .selected');
		if(yo.accountDisplayMode){//if they click on PAST, NOW or FUTURE after visiting account settings wipe the account settings stuff and use the cache and then delete it
			yo.accountDisplayMode=false;
			
			yo.timelyRegion = 'body';//replace the body with timely over again
			var options={}
			options.version = Application.Wrapper.getModuleVersion(PARAM.id, 'latest');
			options.moduleId = PARAM.id;
			options.mode = view;
			$('.options-bar').removeClass('desktop');
			Application.Appcore.loadApplication(options);
			
			//Application.Appcore.loadModule({ moduleKey : '_10003204', moduleId : '10003204', el:'#main-container', region :'#main-container', divId:'#main-container'});
			//Application.Appcore.loadModule({ moduleKey : "10003204_", moduleId : '10003204', region :'#main-container',  mode:view});
			$('.past').removeClass('selected').addClass('default');
			$('.now').removeClass('selected').addClass('default');
			$('.future').removeClass('selected').addClass('default');
		}
		switch (view) {
			case 'past':
				if(selected.hasClass('past')){
					return;
				}else{
					yo.activeContainer = 'past';
					selected.removeClass('selected').addClass('default');
					$('.past').removeClass('default').addClass('selected');
					if(selected.hasClass('future')){
						yo.NG.animate('past','future','right');
					}else{
						yo.NG.animate('past','now','right');
					}
				}
				break;
			case 'now':
				if(selected.hasClass('now')){
					return;
				}else{
					yo.activeContainer='now';
					selected.removeClass('selected').addClass('default');
					$('.now').removeClass('default').addClass('selected');
					if(selected.hasClass('past')){
						yo.NG.animate('now','past','left');
					}else{
						yo.NG.animate('now','future','right');
					}
				}
				break;
			case 'future':
				if(selected.hasClass('future')){
					return;
				}else{
					yo.activeContainer='future';
					selected.removeClass('selected').addClass('default');
					$('.future').removeClass('default').addClass('selected');
					if(selected.hasClass('past')){
						yo.NG.animate('future','past','left');
					}else{
						yo.NG.animate('future','now','left');
					}
					
				}
				break;
		}
	}
	/***
	 * animates divs in a direction on and off the screen 
	 * @param newpage is id of new page to move on
	 * @param oldpage is id of old page to move off
	 * @param direction is the direction to move them
	 */
	,animate :function (newpage,oldpage,direction){
		
		var bodyWidth = document.body.clientWidth;
		if(direction=="right"){
			$( "#"+newpage ).css("left",bodyWidth*-1);
			$( "#"+oldpage ).animate({
			    left: bodyWidth
			}, {
			    duration: PARAM.animationSpeed,
			    step: function( now, fx ){
			      $( "#"+oldpage ).css( "left", now );
			    }
			});
			$( "#"+newpage ).animate({
			    left: 0
			}, {
			    duration: PARAM.animationSpeed,
			    step: function( now, fx ){
			      $( "#"+newpage ).css( "left", now );
			    }
			});
		}else if(direction=="left"){
			$( "#"+newpage ).css("left",bodyWidth);
			$( "#"+oldpage ).animate({
			    left: bodyWidth*-1
			}, {
			    duration: PARAM.animationSpeed,
			    step: function( now, fx ){
			      $( "#"+oldpage ).css( "left", now );
			    }
			});
			$( "#"+newpage ).animate({
			    left: 0
			}, {
			    duration: PARAM.animationSpeed,
			    step: function( now, fx ){
			      $( "#"+newpage ).css( "left", now );
			    }
			});
		}
			
	}
	
	, doTagSearch: function(keywrd){
		//overlay view so we can come back to this one
		$("#selectedTagName").html(keywrd);
		$("#selectedTagNameHeader").show();
		
		$("#advancedSearch").hide();
		$("#currentFiltersDisplay").hide();
		
		//TODO: remove toolbar-center if not needed for new design
		//$("#toolbar-center").show();
		//$(".main-btn-bar-right").hide();
		
		$("#searchBoxContainer").hide();
		$("#backToSearch").css("display", "inline-block");
		
		var container = document.createElement("div");
		//container.className = "searchResultsWrapper";
		container.id = "appendedSearchResultsContainer"; 
		yo.activeContainer = "appendedSearchResultsContainer";
		
		var header = document.createElement("div");
		header.id = "appendedSearchResultsContainerHeaderWrapper";
		
		//header.innerHTML = "<div class='searchResultsContainerHeader'>"+__["Transactions"]+"</div>";
		var unCheckedCheckbox = (yo.IE==8) ? '<i class="i-z0027unchecked"></i>' : params.svg.iconUnchecked;
       		
   		header.innerHTML = 	'<div id="editDeleteTagHeader" class="disabled">\
				<div class="center">\
					<div tabindex="0" role="button" class="btn" id="editTagBtn" aria-label="Edit tag">EDIT TAG</div>\
					<div tabindex="0" role="button" class="btn" id="deleteTagBtn" aria-label="Delete tag">DELETE TAG</div>\
				</div>\
			</div>'+
   		
   		'<div class="searchResultsContainerHeader">'+
   		
   		'<div class="sideBySideColumn titleCtr" title="TRANSACTIONS">'+
        	'<span class="checkboxCtr multiSelectCheck" id="selectAllTagTrans" tabindex="0" role="checkbox">'+unCheckedCheckbox+
        	'</span>'+__["TRANSACTIONS"]+'</div>'+
        	
        	'<div class="editBtnCtr">\
			<a href="#" role="button" class="editTrans" aria-label="Add tag">'+__["EDIT"]+'</a>\
			</div>\
		</div>'+
    	'</div>';
        	
		$(container).append(header);
		
		var body = document.createElement("div");
		body.id = "appendedSearchResults";
		$(container).append(body);
		
		$("#searchResultsSecondary").append(container);

		//bind functions to enable multi txn editing
		

		if(params.moduleSwitch.transModule=="on"){
			var filter = new yo.TransactionFilter();
			filter.set({keyword: $("#searchInput").val(),mode:'tag_search'});
			Application.Appcore.loadModule({ moduleKey : "10003204_10003507", moduleId : '10003507', region :'#appendedSearchResults',  mode:filter});
			yo.activeContainer = "searchResultsContainer";
			
			yo.resize();
		}
		
		//show secondary, hide primary
		$("#searchResultsSecondary").show();
		$("#searchResultsPrimary").hide();
		
		$("#mobileSearchCancel").hide();
    }
    

   	, editTagSave: function(){
   		yo.NG.closeLightBox();	
	    		 // Show success message.
		var successMsg = $('.topMsgCtr');
		var origMsg = $(successMsg[0]).find('p').html();
		$(successMsg[0]).find('p').html('Tag edited successfully.');
    	
    	var msgNode = successMsg[0].cloneNode(true);
    	msgNode.className = msgNode.className.replace('hide','');
    	if(yo.msgNode){
    		document.body.removeChild(yo.msgNode);
    		delete yo.msgNode;
	    }
    	yo.msgNode = msgNode;
    	document.body.appendChild(msgNode);
    	
	    //Remove the message after 8sec
	    setTimeout(function() {
		    if(yo.msgNode){
	    		document.body.removeChild(yo.msgNode);
	    		delete yo.msgNode;
	    		$(successMsg[0]).find('p').html(origMsg);
		    }
		}, 10000);
   	}
    
	, closeLightBox : function(){
		$("#black_overlay_editTag").hide();
		$('#body-content-js')[0].removeChild(yo.modal);
		delete yo.modal;
		
    	//TODO: return focus to something on the hpage 
	}
	
	, clearTags: function(){
		$("#tagsSearchResultsContainerHeaderWrapper").html("");
		$("#tagsSearchResults").html("");
		
		$("#selectedTagName").html("");
		$("#selectedTagNameHeader").hide();
	}
	
	, backToSearch: function(){
		$("#searchBoxContainer").show();
		$("#appendedSearchResultsContainer").remove();
		$("#selectedTagName").html("");
		$("#selectedTagNameHeader").hide();
		
		$("#searchResultsSecondary").hide();
		$("#searchResultsPrimary").show();
		
		$("#backToSearch").hide();
		$("#advancedSearch").show();
		$("#currentFiltersDisplay").show();
		
		if(yo.NG.isMobilePhone()){
			$("#mobileSearchCancel").show();
		}
		yo.activeContainer = "searchResultsContainer";
	}
	
	, getTxnFilter: function(){
		if(this.txnFilter==null){
			this.txnFilter = new yo.TransactionFilter();
		}
		return this.txnFilter;
		
	}
	
	, doDateSearch: function(){
	
		yo.NG.showHideCalendar();
		var fromDateInput = $("#fromDate");
		var fromDate = $("#fromDate").val();
		if(yo.NG.isMobilePhone() || yo.NG.isTablet()){
			fromDateInput = $("#fromDate.mobile");
			fromDate = $("#fromDate.mobile").val(); 
		}
		var toDateInput = $("#toDate"); 
		var toDate = $("#toDate").val();
		if(yo.NG.isMobilePhone() || yo.NG.isTablet()){
			toDateInput = $("#toDate.mobile"); 
			toDate = $("#toDate.mobile").val(); 
		}
		
		if(fromDate=="" || toDate=="") return;//don't run search unless user entered both dates 
		
		var frDt = moment(fromDate);
		var toDt = moment(toDate);

		//validate
		if(frDt>toDt) {
			fromDateInput.addClass("error");
			toDateInput.addClass("error");
			$("#dateFilterDropdown .errorMsg").addClass("active");
			return;
		}else{
			fromDateInput.removeClass("error");
			toDateInput.removeClass("error");
			$("#dateFilterDropdown .errorMsg").removeClass("active");
		}
		
		this.getTxnFilter().set({fromDate: frDt.valueOf()});
		this.getTxnFilter().set({toDate: toDt.valueOf()});
		
		//TODO:get user pref for format
		$("#currentDateFilter .from").html(moment(frDt).format("MM/DD/YYYY"));
		$("#currentDateFilter").addClass("active");
		
		//TODO:get user pref for format
		$("#currentDateFilter .to").html((toDt).format("MM/DD/YYYY"));
		$("#currentDateFilter").addClass("active");
	
		/* if($("#fromDate").val()!=""){
			var toDatePrepop = moment().add(1, "month");
			this.getTxnFilter().set({toDate:toDatePrepop.valueOf()});
		}*/
		yo.NG.renderSearch();
	}
	
	, runAmountSearch: function(fromAmount, toAmount, fromAmountInput, toAmountInput){
		if(toAmount=="" || fromAmount=="") return;
		
		//validate
		if(parseInt(toAmount)<=parseInt(fromAmount)) {
			fromAmountInput.addClass("error");
			toAmountInput.addClass("error");
			$("#amountFilterDropdown .errorMsg").addClass("active");
			return;
		}else{
			fromAmountInput.removeClass("error");
			toAmountInput.removeClass("error");
			$("#amountFilterDropdown .errorMsg").removeClass("active");
		}
		
		this.getTxnFilter().set({fromAmount:fromAmount});
		$("#currentAmountFilter .from").html(fromAmount);
		$("#currentAmountFilter").addClass("active");
	
	
		this.getTxnFilter().set({toAmount:toAmount});
		$("#currentAmountFilter .to").html(toAmount);
		$("#currentAmountFilter").addClass("active");
		
		yo.NG.renderSearch();
	}
	
	, doAmountSearchWrapperForAndroid: function(){
		if(yo.device!="Android") return;
		
		//android doesn't give us the keycode, but it pulls up the keypad
		//so the assumption is the values will always be numbers
		//just run the search.
		
		yo.NG.runAmountSearch($("#fromAmount.mobile").val(), $("#toAmount.mobile").val(), $("#fromAmount.mobile"), $("#toAmount.mobile"));
		
	}
	
	, doAmountSearch: function(e){
		
		if(yo.NG.numbersOnly(e)){
			var fromAmountInput = $("#fromAmount");	
			var fromAmount = $("#fromAmount").val(); 
			if(yo.NG.isMobilePhone() || yo.NG.isTablet()){
				fromAmountInput = $("#fromAmount.mobile");	
				fromAmount = $("#fromAmount.mobile").val();
			} 
				
			var toAmountInput = $("#toAmount");
			var toAmount = $("#toAmount").val(); 
			if(yo.NG.isMobilePhone() || yo.NG.isTablet()){
				toAmountInput = $("#toAmount.mobile");
				toAmount = $("#toAmount.mobile").val();
			} 
		
			yo.NG.runAmountSearch(fromAmount, toAmount, fromAmountInput, toAmountInput);
		}
	}
	
	, doCategorySearch: function(el){
		yo.NG.showCategoryFilter($("#categoryFilter"));
		
		$(".filter-dropdown .selectedCategoryIcon").removeClass("active");//remove all
		$(el).find(".selectedCategoryIcon").addClass("active");
		
		$("#currentCategoryFilter .currentFilterValue").html(el.innerHTML);
		$("#currentCategoryFilter").addClass("active");
			
		this.getTxnFilter().set({categoryId:$(el).find(".catOptionValue").html()});
		
		yo.NG.renderSearch();
	}
	
	, renderSearch : function(){

		if(params.moduleSwitch.transModule=="on"){
			//console.log(this.getTxnFilter());
			this.getTxnFilter().set({mode:'search'});
			Application.Appcore.loadModule({ moduleKey : "10003204_10003507", moduleId : '10003507', region :'#searchResults', mode:this.getTxnFilter()});
			
			$("#searchResultsContainer").removeClass("overlay");
			
			yo.activeContainer="searchResultsContainer";
			
			yo.resize();
			
			if(yo.device=="iPad"){
				setTimeout(function(){
					$("#searchResultsContainer").css("height", document.body.scrollHeight+"px");
					//TODO: if this works and is tested, can be added to the resize() fn
				}, 100);	
			}
			
			/*if(yo.device=="Android"){
				setTimeout(function(){
					yo.NG.unresize();
				}, 1000);
			}*/
		}
	}
	
	, rerunSearchIfFilterExists: function(){
		if(yo.NG.filterHasCriteria()){
			yo.NG.renderSearch();
		}else{
			yo.NG.clearSearchContainers();
		}
	}
	
	, filterHasCriteria: function(){
		var filter = this.getTxnFilter();
		if(filter.get('keyword')!="") return true;
		if(filter.get('categoryId')!="") return true;
		if(filter.get('fromAmount')!=null) return true;
		if(filter.get('toAmount')!=null) return true;
		if(filter.get('fromDate')!=null) return true;
		if(filter.get('toDate')!=null) return true;
		return false;
	}
	/**Loads the past view's Transactions data'
	 */
	, renderPast : function () {
		if(params.moduleSwitch.transModule=="on"){
			var filter = new yo.TransactionFilter();
			filter.set({mode:'past'});
       		Application.Appcore.loadModule({ mode:filter, moduleKey : "10003204_10003507", moduleId : '10003507', el:'#postedTransactions', region :'#postedTransactions', divId:'#postedTransactions'});
        }
	}
	/**Lazy loads the future view's bills data
	 */
	, renderFuture: function () {
		
		if(params.moduleSwitch.transModule=="on"){
			var filter = new yo.TransactionFilter();
			filter.set({mode:'future'});
			Application.Appcore.loadModule({ mode:filter, moduleKey : "10003204_10003507", moduleId : '10003507', el:'#scheduledTransactions', region :'#scheduledTransactions', divId:'#scheduledTransactions'});
		}
		
		//this works but uncomment once we get to bills story as it is not looking perfect right now
		if(params.moduleSwitch.billsModule=="on"){
			if(yo.IE==8){
				yo.requireCSS(PARAM.billsId);
			}
			Application.Appcore.loadModule({ moduleKey : "10003204_"+PARAM.billsId, moduleId : PARAM.billsId, el:'#bills', region :'#bills', divId:'#bills'});
		}
		
	}
	
	/***loadUserSettings function, loads js and styles for it only on click of button
	 * nnede duplicate one because acocunts needs ot be able to work atomically and this cannot call the one in acounts until accoutns is loaded which is what this function does
	 */
	,loadUserSettings:function(){
		yo.uiLoad.start();
		if(yo.IE==8){
			yo.requireCSS(PARAM.accountsId);
		}
		yo.accountsRegion = '#body-content-js';
		//default display mode is by FI
    	yo.accountDisplayMode = 'fi';
    	var selected = $('#primaryNav .selected');
		yo.activeContainer = 'body-content-js';
		var main = $('#main-container')[0];
		yo.timelyBodyCache = main.innerHTML;
		selected.removeClass('selected').addClass('default');
		$('.options-bar').addClass('desktop');
		Application.Appcore.loadModule({ moduleKey : "10003204_"+PARAM.accountsId, moduleId : PARAM.accountsId, el:'#body-content-js', region:false, divId:'#body-content-js'});
		var bd = $('#body-content-js');
		bd[0].style.overflowY="auto";
		bd[0].style.overflowX="hidden";
		Foundation.libs.reveal.close();//all Foundation methods can be called globally hooray!
		bd.attr('tabindex',0);
		bd.focus();
	}

	/*,loadUserNotificationSettings:function(){
		yo.NG.showSearch();
		$('#searchBoxContainer').hide();
		$('#advancedSearch').hide();
		$('#searchResults').html(imTempMakeViewNS());
		yo.activeContainer="searchResultsContainer";
		yo.resize();
		Foundation.libs.reveal.close();//all Foundation methods can be called globally hooray!
	}*/

	,toggleTheButton:function(btn){
		$(btn).siblings(".sel").removeClass("sel");
		$(btn).addClass("sel");
		
	}
	/**date format used by Highcharts*/
	,dateFormat: function(o) {

		var t = o.date || o;	
		if(typeof(t)=="string"){
			t = parseInt(t);
		}
		var month = Highcharts.dateFormat('%m', t),
			year = Highcharts.dateFormat('%Y', t),
			day = Highcharts.dateFormat('%d', t)
		return (yo.formatDate(year + "-" + month + "-" + day))	

	}
	
	/**
	 *Helps us know what is a Bill Type of account 
	 */
	,isABillType: function(val){
		/*summary returns true if type is a bill type*/
		val= val.toString().toLowerCase()
		if(val=="bills"||val=="telephone"||val=="cable_satellite"||val=="minutes"||val=="utilities"||val=="isp"||val=="bill_payment"){
			return true;
		}
		return false;
	}
	/**
	 *	Retuns a correct label for a Container
	 */
	,returnCorrectLabel: function(){
		/*returns correct label from the translated strings according to the account type*/
		var val = '';
		if(yo.NG.isABillType(yo.accountType))return PARAM.bTitle;
		if(yo.accountType=='insurance')return PARAM.bTitle;
		if(yo.accountType=='credits')return PARAM.cTitle;
		if(yo.accountType=='realestate')return PARAM.hTitle;
		if(yo.accountType=='stocks')return PARAM.iTitle;
		if(yo.accountType=='loans'||yo.accountType=='mortgage')return PARAM.lTitle;
		return PARAM.xTitle;
	}

	, numbersOnly : function(e){
		
		var k = (e.which) ? e.which : e.keyCode;
      	var a = [8, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57];//number keyCodes only, for real 
		
		if (!($.inArray(k,a)>=0)){
			if(e.preventDefault){//IE8 doesn't have preventDefault
				e.preventDefault();
			}
			return false;
       	}

       	return true;
	}
	
	, showHideCalendar: function(calElement){
		if(yo.NG.isMobilePhone()) return;
		
		var on = calElement && $("#"+calElement).hasClass("active");
		 
		$(".calendarPicker").removeClass("active");
		
		if(calElement && !on){
			$("#"+calElement).addClass("active");
		}
	}
	
	, blurFilters: function(event){
		if(typeof(event.srcElement)!="undefined"){
			event.target = event.srcElement;
		}
		if(event.target.id=="searchResultsContainer" || event.target.id=="searchResultsPrimary" || event.target.id=="filtersBar" || event.target.className=="center"){
			$(".filterBox.active").removeClass("active");//all
			$(".dropdowns>div.active").removeClass("active");//remove all active dropdowns
			yo.closeDropdownSearch();
		}
	}
};

/** Generates html for Task Menu */
yo.getTaskMenuHtml = function(parentId) {
	var content ='<li><div class="icon">b</div><a href="#">'+__["Pay a Bill"]+'</a></li>' +
			    '<li><div class="icon">g</div><a href="#">'+__["Create a Goal"]+'</a></li>' +
			    '<li><div class="icon">c</div><a href="#">'+__["Start a Challenge"]+'</a></li>' +
			    '<li><div class="icon">a</div><a href="#">'+__["Add an Account"]+'</a></li>';
			    content = yo.getModalTooltip('taskmenu',content);
	//return content;
	
	var parentDiv = document.getElementById(parentId);
	parentDiv.innerHTML += content;
};
	

PARAM.viewFrameIds = params["viewFrameIds"];
PARAM.viewFrameIds = PARAM.viewFrameIds.split(',');//used in base.js to determine what to resize
PARAM.zillowFooterNoteEnabled = params["zillowFooterNoteEnabled"];
PARAM.zillowImageUrl = params["zillowImageUrl"];
PARAM.zillowSiteUrl = params["zillowSiteUrl"];
PARAM.zillowTermsOfUseUrl = params["zillowTermsOfUseUrl"];
PARAM.zillowWhatIsZestimateUrl = params["zillowWhatIsZestimateUrl"];
PARAM.zillowImageAltText = params["zillowImageAltText"];
PARAM.realEstateCSID = params["realEstateCSID"];
PARAM.item_id_emb_param = params["item_id"];
PARAM.account_id_emb_param = params["item_account_id"];
PARAM.account_type_emb_param = params["container"];
PARAM.markerLineColor = params["markerLineColor"];
PARAM.chartLineColor = params["chartLineColor"];//giving unique name since other finapps may want a different line color or multiple
PARAM.bTitle = __["Amount Due"];
PARAM.cTitle = __["Account Balance"];
PARAM.hTitle = __["Home Value"];
PARAM.iTitle = __["Investment Balance"];
PARAM.lTitle = __["Principal Balance"];
PARAM.xTitle = __["Balance"];
PARAM.animationSpeed = params["animationSpeed"];
PARAM.colorStops = params["gradientChartColors"];
PARAM.transId = params["transModule"];
PARAM.accountsId = params["accountsModule"];
PARAM.billsId = params["billsModule"];
PARAM.gridLineColor = params["gridLineColor"];
PARAM.chartLabelColor = params["chartLabelColor"];
PARAM.chartLabelSize = params["chartLabelSize"];
PARAM.chartLabelFont = params["chartLabelFont"];
PARAM.showAddAnAccountLink = params["showAddAnAccountLink"];
PARAM.showTasks = params["showTasks"];
PARAM.showLogo = params["showLogo"];
PARAM.showSearch = params["showSearch"];
PARAM.popDialog = __[" - Opens a simulated dialog"];
PARAM.comfortableBalance = 6000;//need to get from back end api call
PARAM.mainAccount = "10445570_20537601";//needs to come from api


// Init accounts
yo.api('/services/Preference/all/', function(data){
	PARAM.prefData = data;
});			

var vent = new _.extend({}, Backbone.Events);


$(function(){
	setTimeout(function(){
		yo.NG.writeSearchCategories();
	}, 2000);
	  
});

Backbone.View.prototype.closeView = function() {
    if (this.onClose) {
        this.onClose();
    }
    this.remove();
    this.stopListening();
    
    Backbone.View.prototype.remove.call(this);
    //this = null;
};



var imTempMakeViewNS = function () {
	var out = "";
	var showPushSettings = PARAM.isMobile && yo.device == 'Android'; // enabled for downloadable android only!


	out += "<div class='pageheader'>\
				<div class='panel-sub-title text-center' style='color:#fff;text-transform:uppercase;'>Notification Settings</div>\
			</div>\
			<div class='settingsView' style='margin-top:2em;'>\
				<h3>Notification Settings</h3>";
	out += "<div class='uiBoxCluster'>";
	out +=   imTempMakeRow({'txtLabel':'Methods', 'cssClass':'row-heading'});
	  out += imTempMakeRow({'txtLabel':'E-mail',  'toggle':true, 'id':'email'});
	  out += imTempMakeRow({'txtLabel':'SMS',     'toggle':true, 'id':'sms'});
	if (showPushSettings) {
	  out += imTempMakeRow({'txtLabel':'Push',    'toggle':true, 'id':'push'});
	}
	out += "</div>";
	out += "<dl class='accordion'><dd class='accordion-navigation'><h4>Credit Card Balance</h4></dd></dl>";
	out += "<div class='uiBoxCluster'>";
	out += imTempMakeRow({'txtLabel':'Cumulative Balance', 'toggle':true, 'id':'totalbalance',
				'toggleAction':'onclick="handleSettingSwitch(this)"',
				'extraMarkup':"<div class='adjustText'>Notify me when my credit card balance across all cards exceeds:</div>\
							   <div class='pctSignBox'><input type='tel' name='limit' id='limitPct' maxlength='3' onkeydown='return inputNumPct.filter(this,event)' onkeyup='inputNumPct.bound(this)' onblur='inputNumPct.finish(this)' onfocus='inputNumPct.init()' voidvalue='30%' voidmin='1' voidmax='100' class='adjustTextbox' value='30%' disabled /><span class='pctSignSymbol' style='' id='limitPctSymbol' onclick='inputNumPct.invoke()'>%</span></div>",
				'tinyText':'A cumulative credit card balance of over 30% will affect your credit score negatively. Turn on to receive an alert when your cumulative balance goes over a certain percentage.'
			});
	out += "</div>";

	return out + "</div>";
}
var inputNumPct = {
	'pctSymbol': null,
	'pctSymbolRightOffset': function (inputValue, numOffset) {
		var inputLength = inputValue.toString().length;
		if (numOffset) {inputLength += numOffset;}
		if (inputLength==2) return "0.9rem";
		if (inputLength==1) return "1.15rem";
		if (inputLength<=0) return "1.35rem";
		if (inputLength>=3) return "0.7rem";
		return "0.7rem";
	},
	'invoke': function () {
		var pctField = document.getElementById('limitPct');
		if (pctField) {pctField.focus();}
	},
	'init': function () {
		var pctField = document.getElementById('limitPct');
		// remove % sign from input field
		pctField.value = parseInt(pctField.value);
		this.pctSymbol = document.getElementById('limitPctSymbol');
		this.pctSymbol.style.right = inputNumPct.pctSymbolRightOffset(pctField.value);
		// permanently display superimposed % sign over input field
		this.pctSymbol.style.display = 'block';
	},
	'finish': function (obj) {
		var defaultValue = false;
		var limitMax = parseInt(obj.getAttribute('voidmax'));
		var limitMin = parseInt(obj.getAttribute('voidmin'));
		var number = parseInt(obj.value);
		if (isNaN(number) || number == 0) {
			defaultValue = true;
		} else if (!isNaN(limitMin) && number < limitMin) {
			number = limitMin;
		} else if (!isNaN(limitMax) && number > limitMax) {
			number = limitMax;
		}
		if (defaultValue) { // fallback to default
			this.pctSymbol.style.display = 'none'; // hide % sign
			obj.value = obj.getAttribute('voidvalue');
		} else {
			// show newly updated number, W/O % sign, since superimposed on is there!
			obj.value = number; // +'%'; // the % sign append - not needed
		}
	},
	'bound': function(obj) {
		// prevent user input greater than $limitMax
		var limitMax = parseInt(obj.getAttribute('voidmax'));
		if (!isNaN(limitMax) && obj.value > limitMax) {
			this.pctSymbol.style.right = inputNumPct.pctSymbolRightOffset(obj.value);
			obj.value = limitMax;
		}
	},
	'filter': function (obj,evt) {
		var evt = evt || event;
		var key = evt.keyCode ? evt.keyCode : evt.which;
		var limitMax = parseInt(obj.getAttribute('voidmax'));
		// exit on Enter
		if (key == 13) { // on ENTER
			obj.blur();
			return true;
		}
		// if tab is pressed
		if (key == 9) {
			return true;
		}
		// check for special case keys
		switch (key) {
			case 46: // delete
			case  8: // backspace
				// -1 to account for LESS ONE number BEFORE return updates input object string
				this.pctSymbol.style.right = inputNumPct.pctSymbolRightOffset(obj.value, -1);
				return true

			case 16: // shift
			case 35: // end
			case 36: // home
			case 37: // left
			case 38: // up
			case 39: // right
			case 40: // down
				return true;
		}
		// check if number
		var number = parseInt(String.fromCharCode(key));
		if (!evt.shiftKey && !isNaN(number)) {
			// +1 to account for ONE MORE number BEFORE return updates input object string
			this.pctSymbol.style.right = inputNumPct.pctSymbolRightOffset(obj.value, +1);
			return true;
		}
		// else if all fails then false exit which will dismiss keypress
		return false;
	}
}

var imTempMakeRow = function(opts) {
	var out = "";
	out += "<dl class='accordion'> \
				<dd class='accordion-navigation'> \
					<div class='clearfix row-middle " + opts.cssClass + "'> \
					  <div class='clearfix'>\
						<div class='textEntry'>" + opts.txtLabel + "</div>";
	if (opts.toggle) {
	out += "			<div class='right'>\
							<div class='switch' " + (opts.toggleAction||"") + ">\
								<input  id='userNotificationsSwitch_" + opts.id + "' type='checkbox'>\
								<label for='userNotificationsSwitch_" + opts.id + "'><p class='toggleText'>OFF</p></label>\
							</div>\
						</div>";
	}
	if (opts.extraMarkup) {
	out += "<div class='clearfix settingAdjusters settingInactive' id='userNotificationsSwitch_" + opts.id + "_Target'>" + 	opts.extraMarkup + "</div>";
	}
	out += "</div>";
	if (opts.tinyText) {
	out += "<div class='adjustInfoText' id='userNotificationsSwitch_" + opts.id + "_nomobile'>" + opts.tinyText + "</div>";
	}
	out += "		</div>\
				</dd>\
			</dl>";
	return out;

}

var handleSettingSwitch = function(src){
  var checkbox = $(src).find("input[type=checkbox]").get(0);
  var targetDiv = $("#" + checkbox.id + "_Target");
  var targetInput = targetDiv.find("input[type=tel]").get(0);
  var nomobile   = $("#" + checkbox.id + "_nomobile");
  if (!checkbox || !targetDiv || !targetInput) {
  	return; // exit on error
  }
  if (checkbox.checked) {
    checkbox.checked = false;
    targetInput.disabled  = true;
    targetDiv.addClass("settingInactive");
    if (nomobile && nomobile.hasClass("mobileBoxHide")) {
      nomobile.removeClass("mobileBoxHide");
    }
  } else {
    checkbox.checked = true;
    targetInput.disabled  = false;
    targetDiv.removeClass("settingInactive");
    if (nomobile && !nomobile.hasClass("mobileBoxHide")) {
      nomobile.addClass("mobileBoxHide");
    }
  }
};

