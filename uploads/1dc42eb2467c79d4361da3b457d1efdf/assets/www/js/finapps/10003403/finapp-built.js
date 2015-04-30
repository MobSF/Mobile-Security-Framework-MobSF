define('10003403_js/finappConfig',[],function(){ return ({
	"id" : "10003403",
	"name":"Accounts",
	"version" : "src",
	"modules" : [
	{
		"id" : "10003600",
		"name" : "Fast Link",
		"version" : "src",
	}]
}); });
define('10003403_js/models/AccountsModel',['10003403_js/models/AccountsModel'],function(){
   var AccountsModel = Backbone.Model.extend({});
    return AccountsModel;
});

define('10003403_js/collections/AccountsCollection',['10003403_js/models/AccountsModel'],function(AccountsModel){
    var AccountsCollection = Backbone.Collection.extend({
        model: AccountsModel
    });
    return AccountsCollection;
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

define('10003403_js/compiled/finappCompiled',['handlebars'], function(Handlebars) {
  var template = Handlebars.template, templates = Handlebars.templates = Handlebars.templates || {};
templates['AccountDetails'] = template(function (Handlebars,depth0,helpers,partials,data) {
  helpers = helpers || Handlebars.helpers;
  var buffer = "", stack1, stack2, stack3, foundHelper, tmp1, self=this, functionType="function", helperMissing=helpers.helperMissing, undef=void 0, escapeExpression=this.escapeExpression, blockHelperMissing=helpers.blockHelperMissing;

function program1(depth0,data) {
  
  var buffer = "", stack1;
  buffer += "\n";
  foundHelper = helpers.showAccountSettingsLink;
  stack1 = foundHelper || depth0.showAccountSettingsLink;
  tmp1 = self.program(2, program2, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  if(foundHelper && typeof stack1 === functionType) { stack1 = stack1.call(depth0, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack1, tmp1); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n";
  return buffer;}
function program2(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n<!--div class=\"pagefooter\">\n	<div class=\"panel-sub-title text-center\">\n		<div class=\"sideBySideColumnLeft greyborder\"><span class=\"acctDetailslink selected\" title=\"";
  stack1 = "Transactions";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\">";
  stack1 = "Transactions";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</span></div>\n		<div class=\"sideBySideColumnRight greyborder \" ><span class=\"acctSettingslink\" title=\"";
  stack1 = "Settings";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\">";
  stack1 = "Settings";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</span></div>\n	</div>\n</div-->\n";
  return buffer;}

  buffer += "<div class=\"pageheader\">\n	<div class=\"panel-sub-title text-center\">";
  stack1 = "Account Details";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</div>\n</div>\n<span class=\"leftArrow\" title=\"";
  stack1 = "back";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\"></span>	\n<div class=\"accountDetailsHeader text-center\"> <!--class=\"fixed sticky\" style=\"background-color:#003b72\">-->\n	<!--div class=\"medium-font\"><span class=\"primaryAccountIcon\"></span>Primary Spending</div-->\n	<div class=\"panel-sub-title\">";
  foundHelper = helpers.name;
  stack1 = foundHelper || depth0.name;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "name", { hash: {} }); }
  buffer += escapeExpression(stack1) + "</div>\n	<div class=\"medium-font\">";
  foundHelper = helpers.siteName;
  stack1 = foundHelper || depth0.siteName;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "siteName", { hash: {} }); }
  buffer += escapeExpression(stack1) + "</div>\n	<div class=\"separator\"></div>\n	<div class=\"medium-font clearfix\">\n		<div class=\"leftLable \">";
  stack1 = "Current Balance:";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</div>\n		<div class=\"rightSide \"> ";
  foundHelper = helpers.amount1;
  stack1 = foundHelper || depth0.amount1;
  foundHelper = helpers.amount0;
  stack2 = foundHelper || depth0.amount0;
  foundHelper = helpers.money;
  stack3 = foundHelper || depth0.money;
  if(typeof stack3 === functionType) { stack1 = stack3.call(depth0, stack2, stack1, { hash: {} }); }
  else if(stack3=== undef) { stack1 = helperMissing.call(depth0, "money", stack2, stack1, { hash: {} }); }
  else { stack1 = stack3; }
  buffer += escapeExpression(stack1) + " </div>\n	</div>\n	<div class=\"small-font clearfix\">\n		<div class=\"leftLable\">";
  stack1 = "Available:";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</div>\n		<div class=\"rightSide\"> ";
  foundHelper = helpers.amount1;
  stack1 = foundHelper || depth0.amount1;
  foundHelper = helpers.amount0;
  stack2 = foundHelper || depth0.amount0;
  foundHelper = helpers.money;
  stack3 = foundHelper || depth0.money;
  if(typeof stack3 === functionType) { stack1 = stack3.call(depth0, stack2, stack1, { hash: {} }); }
  else if(stack3=== undef) { stack1 = helperMissing.call(depth0, "money", stack2, stack1, { hash: {} }); }
  else { stack1 = stack3; }
  buffer += escapeExpression(stack1) + " </div>\n	</div>\n</div>\n<div class=\"accountTxn\" ><!--Transactions go here--></div>\n";
  foundHelper = helpers.switchEnableAccountSettings;
  stack1 = foundHelper || depth0.switchEnableAccountSettings;
  tmp1 = self.program(1, program1, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  if(foundHelper && typeof stack1 === functionType) { stack1 = stack1.call(depth0, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack1, tmp1); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  return buffer;});
templates['AccountSettings'] = template(function (Handlebars,depth0,helpers,partials,data) {
  helpers = helpers || Handlebars.helpers;
  var buffer = "", stack1, stack2, foundHelper, tmp1, self=this, functionType="function", helperMissing=helpers.helperMissing, undef=void 0, escapeExpression=this.escapeExpression, blockHelperMissing=helpers.blockHelperMissing;

function program1(depth0,data) {
  
  var buffer = "", stack1;
  buffer += "\n<!-- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -->\n\n<div class=\"uiBoxCluster\">\n<dl class=\"accordion\">\n	<dd class=\"accordion-navigation\">\n		<div class=\"clearfix row-middle\">\n			<div class=\"textEntry\">\n				Primary Spending Account\n			</div>\n			<div class=\"right\">\n				<div class=\"switch\">\n					<input id=\"acctSettingSwitch_bank_1\" type=\"checkbox\">\n					<label for=\"acctSettingSwitch_bank_1\"><p class=\"toggleText\">OFF</p></label>\n				</div>\n			</div>\n		</div>\n	</dd>\n</dl>\n<dl class=\"accordion\">\n	<dd class=\"accordion-navigation\">\n		<div class=\"clearfix row-middle\">\n			<div class=\"sideBySideShortLeft\">\n				<div class=\"textEntry\">Nickname</div>\n			</div>\n			<div class=\"sideBySideLong\">\n				<input onpaste=\"return false;\" type=\"text\" name=\"nickname\" value=\"";
  foundHelper = helpers.acctName;
  stack1 = foundHelper || depth0.acctName;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "acctName", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" />\n				";
  foundHelper = helpers.fiName;
  stack1 = foundHelper || depth0.fiName;
  tmp1 = self.program(2, program2, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  if(foundHelper && typeof stack1 === functionType) { stack1 = stack1.call(depth0, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack1, tmp1); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n			</div>\n		</div>\n	</dd>\n</dl>\n</div>\n<dl class=\"accordion\">\n	<dd class=\"accordion-navigation\">\n		<h4>Alerts</h4>\n	</dd>\n</dl>\n<div class=\"uiBoxCluster\">\n<dl class=\"accordion\">\n	<dd class=\"accordion-navigation\">\n		<div class=\"clearfix row-middle\">\n			<div class=\"textEntry\">\n				Low Balance\n			</div>\n			<div class=\"right\">\n				<div class=\"switch\">\n					<input id=\"acctSettingSwitch_bank_2\" type=\"checkbox\">\n					<label for=\"acctSettingSwitch_bank_2\"><p class=\"toggleText\">OFF</p></label>\n				</div>\n			</div>\n			<div class=\"clearfix settingAdjusters settingInactive\" id=\"acctSettingSwitch_bank_2_Target\">\n				<div class=\"adjustText\">Notify me when my balance reaches:</div>\n				<input type=\"tel\" pattern=\"[0-9]*\" name=\"limit\" class=\"adjustTextbox\" value=\"500\" voidvalue='500' voidmin='1' disabled />\n			</div>\n		</div>\n	</dd>\n</dl>\n<dl class=\"accordion\">\n	<dd class=\"accordion-navigation\">\n		<div class=\"clearfix row-middle\">\n			<div class=\"textEntry\">\n				Large Withdrawal\n			</div>\n			<div class=\"right\">\n				<div class=\"switch\">\n					<input id=\"acctSettingSwitch_bank_3\" type=\"checkbox\">\n					<label for=\"acctSettingSwitch_bank_3\"><p class=\"toggleText\">OFF</p></label>\n				</div>\n			</div>\n			<div class=\"clearfix settingAdjusters settingInactive\" id=\"acctSettingSwitch_bank_3_Target\">\n				<div class=\"adjustText\">Notify me when there is a withdrawal over:</div>\n				<input type=\"tel\" pattern=\"[0-9]*\" name=\"limit\" class=\"adjustTextbox\" value=\"500\" voidvalue='500' voidmin='1' disabled />\n			</div>\n		</div>\n	</dd>\n</dl>\n<dl class=\"accordion\">\n	<dd class=\"accordion-navigation\">\n		<div class=\"clearfix row-middle\">\n			<div class=\"textEntry\">\n				Large Deposit\n			</div>\n			<div class=\"right\">\n				<div class=\"switch\">\n					<input id=\"acctSettingSwitch_bank_4\" type=\"checkbox\">\n					<label for=\"acctSettingSwitch_bank_4\"><p class=\"toggleText\">OFF</p></label>\n				</div>\n			</div>\n			<div class=\"clearfix settingAdjusters settingInactive\" id=\"acctSettingSwitch_bank_4_Target\">\n				<div class=\"adjustText\">Notify me when there is a deposit over:</div>\n				<input type=\"tel\" pattern=\"[0-9]*\" name=\"limit\" class=\"adjustTextbox\" value=\"500\" voidvalue='500' voidmin='1' disabled />\n			</div>\n		</div>\n	</dd>\n</dl>\n</div>\n";
  foundHelper = helpers.acctHeldAway;
  stack1 = foundHelper || depth0.acctHeldAway;
  tmp1 = self.program(4, program4, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  if(foundHelper && typeof stack1 === functionType) { stack1 = stack1.call(depth0, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack1, tmp1); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n\n";
  return buffer;}
function program2(depth0,data) {
  
  var buffer = "", stack1;
  buffer += "\n				<div class=\"smallText\">Financial Institution: ";
  foundHelper = helpers.fiName;
  stack1 = foundHelper || depth0.fiName;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "fiName", { hash: {} }); }
  buffer += escapeExpression(stack1) + "</div>\n				";
  return buffer;}

function program4(depth0,data) {
  
  var buffer = "", stack1;
  buffer += "\n<dl class=\"accordion\">\n	<dd class=\"accordion-navigation\">\n		<a href=\"#\" class=\"button btnDeleteAccount\" removeAcctId=\"";
  foundHelper = helpers.acctId;
  stack1 = foundHelper || depth0.acctId;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "acctId", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\">Delete Account</a>\n	</dd>\n</dl>\n";
  return buffer;}

function program6(depth0,data) {
  
  var buffer = "", stack1;
  buffer += "\n<!-- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -->\n\n<div class=\"uiBoxCluster\">\n<dl class=\"accordion\">\n	<dd class=\"accordion-navigation\">\n		<div class=\"clearfix row-middle\">\n			<div class=\"sideBySideShortLeft\">\n				<div class=\"textEntry\">Nickname</div>\n			</div>\n			<div class=\"sideBySideLong\">\n				<input type=\"text\" name=\"nickname\" value=\"";
  foundHelper = helpers.acctName;
  stack1 = foundHelper || depth0.acctName;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "acctName", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" />\n				";
  foundHelper = helpers.fiName;
  stack1 = foundHelper || depth0.fiName;
  tmp1 = self.program(7, program7, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  if(foundHelper && typeof stack1 === functionType) { stack1 = stack1.call(depth0, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack1, tmp1); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n			</div>\n		</div>\n	</dd>\n</dl>\n</div>\n<dl class=\"accordion\">\n	<dd class=\"accordion-navigation\">\n		<h4>Alerts</h4>\n	</dd>\n</dl>\n<div class=\"uiBoxCluster\">\n<dl class=\"accordion\">\n	<dd class=\"accordion-navigation\">\n		<div class=\"clearfix row-middle\">\n			<div class=\"textEntry\">\n				New Bill\n			</div>\n			<div class=\"right\">\n				<div class=\"switch\">\n					<input id=\"acctSettingSwitch_bills_1\" type=\"checkbox\">\n					<label for=\"acctSettingSwitch_bills_1\"><p class=\"toggleText\">OFF</p></label>\n				</div>\n			</div>\n		</div>\n	</dd>\n</dl>\n<dl class=\"accordion\">\n	<dd class=\"accordion-navigation\">\n		<div class=\"clearfix row-middle\">\n			<div class=\"textEntry\">\n				Bill Due\n			</div>\n			<div class=\"right\">\n				<div class=\"switch\">\n					<input id=\"acctSettingSwitch_bills_2\" type=\"checkbox\">\n					<label for=\"acctSettingSwitch_bills_2\"><p class=\"toggleText\">OFF</p></label>\n				</div>\n			</div>\n			<div class=\"clearfix settingAdjusters settingInactive\" id=\"acctSettingSwitch_bills_2_Target\">\n				<div class=\"adjustText mobileBoxShow\">Notify me days before a bill is due:</div>\n				<div class=\"adjustText mobileBoxHide\">Notify me</div>\n				<div class=\"adjustRange clearfix\">\n					<div tabindex=\"0\" role=\"button\" class=\"adjustRangeBtnMinus\" updaterange=\"down\">&ndash;</div>\n					<input type=\"tel\" pattern=\"[0-9]*\" name=\"limit\" class=\"adjustRangeVal\" value=\"3\" maxlength=\"2\" voidvalue='3' voidmin='1' voidmax='10' disabled />\n					<div tabindex=\"0\" role=\"button\" class=\"adjustRangeBtnPlus\" updaterange=\"up\">+</div>\n				</div>\n				<div class=\"adjustText mobileBoxHide\">days before a bill is due.</div>\n			</div>\n		</div>\n	</dd>\n</dl>\n</div>\n";
  foundHelper = helpers.acctHeldAway;
  stack1 = foundHelper || depth0.acctHeldAway;
  tmp1 = self.program(9, program9, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  if(foundHelper && typeof stack1 === functionType) { stack1 = stack1.call(depth0, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack1, tmp1); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n\n";
  return buffer;}
function program7(depth0,data) {
  
  var buffer = "", stack1;
  buffer += "\n				<div class=\"smallText\">Financial Institution: ";
  foundHelper = helpers.fiName;
  stack1 = foundHelper || depth0.fiName;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "fiName", { hash: {} }); }
  buffer += escapeExpression(stack1) + "</div>\n				";
  return buffer;}

function program9(depth0,data) {
  
  var buffer = "", stack1;
  buffer += "\n<dl class=\"accordion\">\n	<dd class=\"accordion-navigation\">\n		<a href=\"#\" class=\"button btnDeleteAccount\" removeAcctId=\"";
  foundHelper = helpers.acctId;
  stack1 = foundHelper || depth0.acctId;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "acctId", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\">Delete Account</a>\n	</dd>\n</dl>\n";
  return buffer;}

function program11(depth0,data) {
  
  var buffer = "", stack1;
  buffer += "\n<!-- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -->\n\n<div class=\"uiBoxCluster\">\n<dl class=\"accordion\">\n	<dd class=\"accordion-navigation\">\n		<div class=\"clearfix row-middle\">\n			<div class=\"sideBySideShortLeft\">\n				<div class=\"textEntry\">Nickname</div>\n			</div>\n			<div class=\"sideBySideLong\">\n				<input onpaste=\"return false;\" type=\"text\" name=\"nickname\" value=\"";
  foundHelper = helpers.acctName;
  stack1 = foundHelper || depth0.acctName;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "acctName", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" />\n				";
  foundHelper = helpers.fiName;
  stack1 = foundHelper || depth0.fiName;
  tmp1 = self.program(12, program12, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  if(foundHelper && typeof stack1 === functionType) { stack1 = stack1.call(depth0, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack1, tmp1); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n			</div>\n		</div>\n	</dd>\n</dl>\n</div>\n<dl class=\"accordion\">\n	<dd class=\"accordion-navigation\">\n		<h4>Alerts</h4>\n	</dd>\n</dl>\n<div class=\"uiBoxCluster\">\n<dl class=\"accordion\">\n	<dd class=\"accordion-navigation\">\n		<div class=\"clearfix row-middle\">\n			<div class=\"textEntry\">\n				Account Update\n			</div>\n			<div class=\"right\">\n				<div class=\"switch\">\n					<input id=\"acctSettingSwitch_rewards_1\" type=\"checkbox\">\n					<label for=\"acctSettingSwitch_rewards_1\"><p class=\"toggleText\">OFF</p></label>\n				</div>\n			</div>\n			<div class=\"clearfix settingAdjusters settingInactive\" id=\"acctSettingSwitch_rewards_1_Target\">\n				<div class=\"adjustText adjustTextShort\">Notify me when the rewards accrued by a transaction exceeds:</div>\n				<div class=\"rewardsBox\">\n					<input type=\"tel\" pattern=\"[0-9]*\" name=\"limit\" class=\"adjustTextbox\" value=\"500\" voidvalue='500' voidmin='1' disabled />\n					<div class=\"rewardsKeyword\">rewards</div>\n				</div>\n			</div>\n		</div>\n	</dd>\n</dl>\n<dl class=\"accordion\">\n	<dd class=\"accordion-navigation\">\n		<div class=\"clearfix row-middle\">\n			<div class=\"textEntry\">\n				Milestone\n			</div>\n			<div class=\"right\">\n				<div class=\"switch\">\n					<input id=\"acctSettingSwitch_rewards_2\" type=\"checkbox\">\n					<label for=\"acctSettingSwitch_rewards_2\"><p class=\"toggleText\">OFF</p></label>\n				</div>\n			</div>\n			<div class=\"clearfix settingAdjusters settingInactive\" id=\"acctSettingSwitch_rewards_2_Target\">\n				<div class=\"adjustText adjustTextShort\">Notify me when my reward balance exceeds:</div>\n				<div class=\"rewardsBox clearfix\">\n					<input type=\"tel\" pattern=\"[0-9]*\" name=\"limit\" class=\"adjustTextbox\" value=\"500\" voidvalue='500' voidmin='1' disabled /> \n					<div class=\"rewardsKeyword\">rewards</div>\n				</div>\n			</div>\n		</div>\n	</dd>\n</dl>\n<dl class=\"accordion\">\n	<dd class=\"accordion-navigation\">\n		<div class=\"clearfix row-middle\">\n			<div class=\"textEntry\">\n				Expiration\n			</div>\n			<div class=\"right\">\n				<div class=\"switch\">\n					<input id=\"acctSettingSwitch_rewards_3\" type=\"checkbox\">\n					<label for=\"acctSettingSwitch_rewards_3\"><p class=\"toggleText\">OFF</p></label>\n				</div>\n			</div>\n			<div class=\"clearfix settingAdjusters settingInactive\" id=\"acctSettingSwitch_rewards_3_Target\">\n				<div class=\"adjustText mobileBoxShow\">Notify me days before my reward expires:</div>\n				<div class=\"adjustText mobileBoxHide\">Notify me</div>\n				<div class=\"adjustRange clearfix\">\n					<div tabindex=\"0\" role=\"button\" class=\"adjustRangeBtnMinus\" updaterange=\"down\">&ndash;</div>\n					<input type=\"tel\" pattern=\"[0-9]*\" name=\"limit\" class=\"adjustRangeVal\" value=\"3\" maxlength=\"2\" voidvalue='3' voidmin='1' voidmax='10' disabled />\n					<div tabindex=\"0\" role=\"button\" class=\"adjustRangeBtnPlus\" updaterange=\"up\">+</div>\n				</div>\n				<div class=\"adjustText mobileBoxHide\">days before my reward expires.</div>\n			</div>\n		</div>\n	</dd>\n</dl>\n</div>\n";
  foundHelper = helpers.acctHeldAway;
  stack1 = foundHelper || depth0.acctHeldAway;
  tmp1 = self.program(14, program14, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  if(foundHelper && typeof stack1 === functionType) { stack1 = stack1.call(depth0, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack1, tmp1); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n\n";
  return buffer;}
function program12(depth0,data) {
  
  var buffer = "", stack1;
  buffer += "\n				<div class=\"smallText\">Financial Institution: ";
  foundHelper = helpers.fiName;
  stack1 = foundHelper || depth0.fiName;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "fiName", { hash: {} }); }
  buffer += escapeExpression(stack1) + "</div>\n				";
  return buffer;}

function program14(depth0,data) {
  
  var buffer = "", stack1;
  buffer += "\n<dl class=\"accordion\">\n	<dd class=\"accordion-navigation\">\n		<a href=\"#\" class=\"button btnDeleteAccount\" removeAcctId=\"";
  foundHelper = helpers.acctId;
  stack1 = foundHelper || depth0.acctId;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "acctId", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\">Delete Account</a>\n	</dd>\n</dl>\n";
  return buffer;}

function program16(depth0,data) {
  
  var buffer = "", stack1;
  buffer += "\n<!-- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -->\n\n<div class=\"uiBoxCluster\">\n<dl class=\"accordion\">\n	<dd class=\"accordion-navigation\">\n		<div class=\"clearfix row-middle\">\n			<div class=\"textEntry\">\n				Primary Spending Account\n			</div>\n			<div class=\"right\">\n				<div class=\"switch\">\n					<input id=\"acctSettingSwitch_credit_1\" type=\"checkbox\">\n					<label for=\"acctSettingSwitch_credit_1\"><p class=\"toggleText\">OFF</p></label>\n				</div>\n			</div>\n		</div>\n	</dd>\n</dl>\n<dl class=\"accordion\">\n	<dd class=\"accordion-navigation\">\n		<div class=\"clearfix row-middle\">\n			<div class=\"sideBySideShortLeft\">\n				<div class=\"textEntry\">Nickname</div>\n			</div>\n			<div class=\"sideBySideLong\">\n				<input onpaste=\"return false;\" type=\"text\" name=\"nickname\" value=\"";
  foundHelper = helpers.acctName;
  stack1 = foundHelper || depth0.acctName;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "acctName", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" />\n				";
  foundHelper = helpers.fiName;
  stack1 = foundHelper || depth0.fiName;
  tmp1 = self.program(17, program17, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  if(foundHelper && typeof stack1 === functionType) { stack1 = stack1.call(depth0, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack1, tmp1); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n			</div>\n		</div>\n	</dd>\n</dl>\n</div>\n<dl class=\"accordion\">\n	<dd class=\"accordion-navigation\">\n		<h4>Alerts</h4>\n	</dd>\n</dl>\n<div class=\"uiBoxCluster\">\n<dl class=\"accordion\">\n	<dd class=\"accordion-navigation\">\n		<div class=\"clearfix row-middle\">\n			<div class=\"textEntry\">\n				Credit Limit\n			</div>\n			<div class=\"right\">\n				<div class=\"switch\">\n					<input id=\"acctSettingSwitch_credit_2\" type=\"checkbox\">\n					<label for=\"acctSettingSwitch_credit_2\"><p class=\"toggleText\">OFF</p></label>\n				</div>\n			</div>\n			<div class=\"clearfix settingAdjusters settingInactive\" id=\"acctSettingSwitch_credit_2_Target\">\n				<div class=\"adjustText\">Notify me when my account balance is approaching my credit limit by:</div>\n				<input type=\"tel\" pattern=\"[0-9]*\" name=\"limit\" class=\"adjustTextbox\" value=\"500\" voidvalue='500' voidmin='1' disabled />\n			</div>\n		</div>\n	</dd>\n</dl>\n<dl class=\"accordion\">\n	<dd class=\"accordion-navigation\">\n		<div class=\"clearfix row-middle\">\n			<div class=\"textEntry\">\n				New Bill\n			</div>\n			<div class=\"right\">\n				<div class=\"switch\">\n					<input id=\"acctSettingSwitch_credit_3\" type=\"checkbox\">\n					<label for=\"acctSettingSwitch_credit_3\"><p class=\"toggleText\">OFF</p></label>\n				</div>\n			</div>\n		</div>\n	</dd>\n</dl>\n<dl class=\"accordion\">\n	<dd class=\"accordion-navigation\">\n		<div class=\"clearfix row-middle\">\n			<div class=\"textEntry\">\n				Bill Due\n			</div>\n			<div class=\"right\">\n				<div class=\"switch\">\n					<input id=\"acctSettingSwitch_credit_4\" type=\"checkbox\">\n					<label for=\"acctSettingSwitch_credit_4\"><p class=\"toggleText\">OFF</p></label>\n				</div>\n			</div>\n			<div class=\"clearfix settingAdjusters settingInactive\" id=\"acctSettingSwitch_credit_4_Target\">\n				<div class=\"adjustText mobileBoxShow\">Notify me days before a bill is due:</div>\n				<div class=\"adjustText mobileBoxHide\">Notify me</div>\n				<div class=\"adjustRange clearfix\">\n					<div tabindex=\"0\" role=\"button\" class=\"adjustRangeBtnMinus\" updaterange=\"down\">&ndash;</div>\n					<input type=\"tel\" pattern=\"[0-9]*\" name=\"limit\" class=\"adjustRangeVal\" value=\"3\" maxlength=\"2\" voidvalue='3' voidmin='1' voidmax='10' disabled />\n					<div tabindex=\"0\" role=\"button\" class=\"adjustRangeBtnPlus\" updaterange=\"up\">+</div>\n				</div>\n				<div class=\"adjustText mobileBoxHide\">days before a bill is due.</div>\n			</div>\n		</div>\n	</dd>\n</dl>\n<dl class=\"accordion\">\n	<dd class=\"accordion-navigation\">\n		<div class=\"clearfix row-middle\">\n			<div class=\"textEntry\">\n				Large Transaction\n			</div>\n			<div class=\"right\">\n				<div class=\"switch\">\n					<input id=\"acctSettingSwitch_credit_5\" type=\"checkbox\">\n					<label for=\"acctSettingSwitch_credit_5\"><p class=\"toggleText\">OFF</p></label>\n				</div>\n			</div>\n			<div class=\"clearfix settingAdjusters settingInactive\" id=\"acctSettingSwitch_credit_5_Target\">\n				<div class=\"adjustText\">Notify me when a transaction (purchase) exceeds:</div>\n				<input type=\"tel\" pattern=\"[0-9]*\" name=\"limit\" class=\"adjustTextbox\" value=\"500\" voidvalue='500' voidmin='1' disabled />\n			</div>\n		</div>\n	</dd>\n</dl>\n<dl class=\"accordion\">\n	<dd class=\"accordion-navigation\">\n		<div class=\"clearfix row-middle\">\n			<div class=\"textEntry\">\n				High Card Balance\n			</div>\n			<div class=\"right\">\n				<div class=\"switch\">\n					<input id=\"acctSettingSwitch_credit_6\" type=\"checkbox\">\n					<label for=\"acctSettingSwitch_credit_6\"><p class=\"toggleText\">OFF</p></label>\n				</div>\n			</div>\n			<div class=\"clearfix settingAdjusters settingInactive\" id=\"acctSettingSwitch_credit_6_Target\">\n				<div class=\"adjustText\">Notify me when my account's running balance exceeds:</div>\n				<input type=\"tel\" pattern=\"[0-9]*\" name=\"limit\" class=\"adjustTextbox\" value=\"5000\" voidvalue='5000' voidmin='1' disabled />\n			</div>\n		</div>\n	</dd>\n</dl>\n</div>\n";
  foundHelper = helpers.acctHeldAway;
  stack1 = foundHelper || depth0.acctHeldAway;
  tmp1 = self.program(19, program19, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  if(foundHelper && typeof stack1 === functionType) { stack1 = stack1.call(depth0, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack1, tmp1); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n\n";
  return buffer;}
function program17(depth0,data) {
  
  var buffer = "", stack1;
  buffer += "\n				<div class=\"smallText\">Financial Institution: ";
  foundHelper = helpers.fiName;
  stack1 = foundHelper || depth0.fiName;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "fiName", { hash: {} }); }
  buffer += escapeExpression(stack1) + "</div>\n				";
  return buffer;}

function program19(depth0,data) {
  
  var buffer = "", stack1;
  buffer += "\n<dl class=\"accordion\">\n	<dd class=\"accordion-navigation\">\n		<a href=\"#\" class=\"button btnDeleteAccount\" removeAcctId=\"";
  foundHelper = helpers.acctId;
  stack1 = foundHelper || depth0.acctId;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "acctId", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\">Delete Account</a>\n	</dd>\n</dl>\n";
  return buffer;}

  buffer += "<div class=\"pageheader\">\n	<div class=\"panel-sub-title text-center\">";
  stack1 = "Account Settings";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</div>\n</div>\n<span class=\"leftArrow\" title=\"";
  stack1 = "back";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\"></span>\n\n\n<div class=\"settingsView\">\n\n\n<h3>Account Settings</h3>\n\n\n";
  foundHelper = helpers.acctContainerType;
  stack1 = foundHelper || depth0.acctContainerType;
  stack1 = (stack1 === null || stack1 === undefined || stack1 === false ? stack1 : stack1.BANK);
  tmp1 = self.program(1, program1, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  if(foundHelper && typeof stack1 === functionType) { stack1 = stack1.call(depth0, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack1, tmp1); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n\n\n\n\n";
  foundHelper = helpers.acctContainerType;
  stack1 = foundHelper || depth0.acctContainerType;
  stack1 = (stack1 === null || stack1 === undefined || stack1 === false ? stack1 : stack1.BILLS);
  tmp1 = self.program(6, program6, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  if(foundHelper && typeof stack1 === functionType) { stack1 = stack1.call(depth0, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack1, tmp1); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n\n\n\n\n";
  foundHelper = helpers.acctContainerType;
  stack1 = foundHelper || depth0.acctContainerType;
  stack1 = (stack1 === null || stack1 === undefined || stack1 === false ? stack1 : stack1.REWARDS);
  tmp1 = self.program(11, program11, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  if(foundHelper && typeof stack1 === functionType) { stack1 = stack1.call(depth0, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack1, tmp1); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n\n\n\n\n";
  foundHelper = helpers.acctContainerType;
  stack1 = foundHelper || depth0.acctContainerType;
  stack1 = (stack1 === null || stack1 === undefined || stack1 === false ? stack1 : stack1.CREDIT);
  tmp1 = self.program(16, program16, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  if(foundHelper && typeof stack1 === functionType) { stack1 = stack1.call(depth0, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack1, tmp1); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n\n\n\n\n<!-- - - - - - END OF CONTAINERS - - - - - - - - - - - - - - - - - - - - - - - - - - -->\n\n\n\n\n</div>\n\n<!--div class=\"pagefooter\">\n	<div class=\"panel-sub-title text-center\">\n		<div class=\"sideBySideColumnLeft greyborder\"><span class=\"acctDetailslink\" title=\"";
  stack1 = "Transactions";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\">";
  stack1 = "Transactions";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</span></div>\n		<div class=\"sideBySideColumnRight greyborder\" ><span class=\"acctSettingslink selected\" title=\"";
  stack1 = "Settings";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\">";
  stack1 = "Settings";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</span></div>\n	</div>\n</div-->		";
  return buffer;});
templates['AccountsList'] = template(function (Handlebars,depth0,helpers,partials,data) {
  helpers = helpers || Handlebars.helpers;
  var buffer = "", stack1, stack2, foundHelper, tmp1, self=this, functionType="function", helperMissing=helpers.helperMissing, undef=void 0, escapeExpression=this.escapeExpression, blockHelperMissing=helpers.blockHelperMissing;

function program1(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += " <span title=\"";
  stack1 = "Press enter to open";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + " ";
  stack1 = "notifications dialog";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\" class=\"right btn small desktop\" tabindex=\"0\" role=\"button\" onclick=\"yo.showNotifications();\" onkeyup=\"if(yo.enter(event)){yo.showNotifications()}\"> ";
  foundHelper = helpers.showNotificationIcon;
  stack1 = foundHelper || depth0.showNotificationIcon;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "showNotificationIcon", { hash: {} }); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += " <span class=\"ada-offscreen\">";
  stack1 = "Press enter to open";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + " ";
  stack1 = "notifications dialog";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</span></span> ";
  return buffer;}

function program3(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n	<div class=\"errorAccounts\" onclick=\"yo.toggleErrorAccounts(event)\" onkeyup=\"if(yo.enter(event)){yo.toggleErrorAccounts(event);}\" tabindex=\"0\" title=\"";
  stack1 = "Press enter to open";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + " ";
  stack1 = "Accounts with errors";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\">\n		<div role=\"button\" class=\"accountErrorText error-title-main full-mobile\" >\n			<span class=\"accountErrorCount\"></span> ";
  stack1 = "Accounts with errors";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "<span class=\"accountErrorArrow\">";
  foundHelper = helpers.showAccountArrow;
  stack1 = foundHelper || depth0.showAccountArrow;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "showAccountArrow", { hash: {} }); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "</span>\n		</div>\n	</div>\n	";
  return buffer;}

function program5(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n<div class=\"footer-bar\"><div title=\"";
  stack1 = "SmartZipText";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\" tabindex=\"0\">";
  foundHelper = helpers.showSmartZipLogo;
  stack1 = foundHelper || depth0.showSmartZipLogo;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "showSmartZipLogo", { hash: {} }); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "</div><div class=\"small-grey-text\"> ";
  stack1 = "SmartZipText";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</div></div>\n";
  return buffer;}

  buffer += "<div class=\"sub-title white center lesspad borderBtm-desktop\">";
  stack1 = "ACCOUNTS";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</div>\n<div class=\"set-width-container\">\n	<table cellpadding=\"0\" cellspacing=\"0\" class=\"sub-title absolute-mobile lesspad top padded-mobile\" style=\"background:none;border:none;\">\n		<tr><td style=\"padding:0px;\">\n	    <div onclick=\"yo.NG.switchView('now');\" onkeyup=\"if(yo.enter(event)){yo.NG.switchView('now');}\" class=\"mobile closeIcon\"> ";
  foundHelper = helpers.showCancelIcon;
  stack1 = foundHelper || depth0.showCancelIcon;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "showCancelIcon", { hash: {} }); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "</div>\n	    <div id=\"viewSelect\" class=\"desktop inline-block\"></div>\n	 	</td><td style=\"padding:0px;width:50%\">\n	 		<span class=\"right btn small\" role=\"button\" tabindex=\"0\" title=\"";
  stack1 = "Add Account";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\" onclick=\"yo.openFastLink('10003403');\">\n	    	<span class=\"desktop inline-block\"> \n	    ";
  foundHelper = helpers.accountLabel;
  stack1 = foundHelper || depth0.accountLabel;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "accountLabel", { hash: {} }); }
  buffer += escapeExpression(stack1) + "</span>\n	    </span>\n	    \n	    </td><td style=\"padding:0px;\"><span class=\"right desktop btn small\" title=\"";
  stack1 = "Press enter to refresh";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + " ";
  stack1 = "All Accounts";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\" tabindex=\"0\" role=\"button\" id=\"refresh\" onclick=\"yo.AC.refresh(this,event);\" onkeyup=\"if(yo.enter(event)){yo.AC.refresh(this,event)}\">\n	    	 ";
  foundHelper = helpers.showrefreshIcon;
  stack1 = foundHelper || depth0.showrefreshIcon;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "showrefreshIcon", { hash: {} }); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n	    	 <span class=\"ada-offscreen\"> ";
  stack1 = "Press enter to refresh";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + " ";
  stack1 = "All Accounts";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + " </span>\n	    <img src=\"";
  foundHelper = helpers.getRefreshImageUrl;
  stack1 = foundHelper || depth0.getRefreshImageUrl;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "getRefreshImageUrl", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" class=\"loader\"/></span>\n	   </td><td style=\"padding:0px;\">\n	    ";
  foundHelper = helpers.switchEnableNotificationSettings;
  stack1 = foundHelper || depth0.switchEnableNotificationSettings;
  tmp1 = self.program(1, program1, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  if(foundHelper && typeof stack1 === functionType) { stack1 = stack1.call(depth0, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack1, tmp1); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n	    <span data-reveal-id=\"mode_options\" title=\"";
  stack1 = "Press enter to open";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + " ";
  stack1 = "Mode";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + " ";
  stack1 = "Dialog";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\" class=\"right mobile btn small\"> ";
  foundHelper = helpers.showfilterActiveIcon;
  stack1 = foundHelper || depth0.showfilterActiveIcon;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "showfilterActiveIcon", { hash: {} }); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += " </span>\n	    </td></tr>\n	</table>\n	<div data-reveal=\"\" class=\"reveal-modal toolTip\" id=\"mode_options\" style=\"display: none; opacity: 1; visibility: hidden; top: 36px; left: 1048px;\">\n	    <div class=\"triangleBorder\"></div>\n	    <div class=\"triangle\"></div>\n	    <div id=\"financialInstitutionMobile\" class=\"modal-link horizontal\" style=\"width:50%;\" tabindex=\"0\" role=\"button\" onclick=\"yo.AC.loadUserSettings();\" onkeyup=\"if(yo.enter(event)){yo.AC.loadUserSettings();}\">\n	        ";
  stack1 = "FINANCIAL INSTITUTION";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + " \n	    </div>\n	    <div id=\"accountTypeMobile\" class=\"modal-link horizontal\" style=\"width:50%;\" tabindex=\"0\" role=\"button\" onclick=\"yo.AC.loadUserSettingsByType();\" onkeyup=\"if(yo.enter(event)){yo.AC.loadUserSettingsByType();}\">";
  stack1 = "ACCOUNT TYPE";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</div>\n	</div>\n	\n	";
  foundHelper = helpers.switchEnableAccountErrors;
  stack1 = foundHelper || depth0.switchEnableAccountErrors;
  tmp1 = self.program(3, program3, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  if(foundHelper && typeof stack1 === functionType) { stack1 = stack1.call(depth0, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack1, tmp1); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += " \n	<div class=\"errorAccountsList\"></div>\n	<div class=\"detailAccountList\"></div>\n</div>\n<div id=\"footer-bar\" class=\"footer-bar mobile\" tabindex=\"0\" role=\"button\" onclick=\"yo.AC.refreshBottomButton(this,event);\" onkeyup=\"if(yo.enter(event)){yo.AC.refreshBottomButton(this,event)}\"> ";
  foundHelper = helpers.showrefreshIcon;
  stack1 = foundHelper || depth0.showrefreshIcon;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "showrefreshIcon", { hash: {} }); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "<span class=\"ada-offscreen\"> ";
  stack1 = "Press enter to refresh";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + " ";
  stack1 = "All Accounts";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</span><img src=\"";
  foundHelper = helpers.getRefreshImageUrl;
  stack1 = foundHelper || depth0.getRefreshImageUrl;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "getRefreshImageUrl", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" class=\"loader\"/> ";
  stack1 = "REFRESH ALL";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + " </div>\n";
  foundHelper = helpers.ifRealEstateFound;
  stack1 = foundHelper || depth0.ifRealEstateFound;
  tmp1 = self.program(5, program5, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  if(foundHelper && typeof stack1 === functionType) { stack1 = stack1.call(depth0, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack1, tmp1); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n";
  return buffer;});
templates['AccountsRow'] = template(function (Handlebars,depth0,helpers,partials,data) {
  helpers = helpers || Handlebars.helpers;
  var buffer = "", stack1, stack2, stack3, foundHelper, tmp1, self=this, functionType="function", helperMissing=helpers.helperMissing, undef=void 0, escapeExpression=this.escapeExpression, blockHelperMissing=helpers.blockHelperMissing;

function program1(depth0,data) {
  
  
  return " hasAccountError ";}

function program3(depth0,data) {
  
  var buffer = "", stack1;
  buffer += "\n						";
  foundHelper = helpers.showAccountSettingsLink;
  stack1 = foundHelper || depth0.showAccountSettingsLink;
  tmp1 = self.program(4, program4, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  if(foundHelper && typeof stack1 === functionType) { stack1 = stack1.call(depth0, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack1, tmp1); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n						";
  return buffer;}
function program4(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n						<span tabindex=\"0\" role=\"button\" title=\"";
  stack1 = "Press enter to open";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\" class=\"accountSettingsIcon settings-btn\"  data-accountid=\"";
  foundHelper = helpers.accId;
  stack1 = foundHelper || depth0.accId;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "accId", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" onclick=\"yo.showAccountSettings(event);\">";
  foundHelper = helpers.showAccountSettingsIcon;
  stack1 = foundHelper || depth0.showAccountSettingsIcon;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "showAccountSettingsIcon", { hash: {} }); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "</span>\n						";
  return buffer;}

function program6(depth0,data) {
  
  var stack1;
  foundHelper = helpers.accError;
  stack1 = foundHelper || depth0.accError;
  tmp1 = self.program(7, program7, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  if(foundHelper && typeof stack1 === functionType) { stack1 = stack1.call(depth0, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack1, tmp1); }
  if(stack1 || stack1 === 0) { return stack1; }
  else { return ''; }}
function program7(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "<span tabindex=\"0\" role=\"button\" title=\"";
  stack1 = "Press enter to open";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\" class=\"accountErrorIcon accountalert-btn\" onkeyup=\"if(yo.enter(event)){yo.showAccountAlerts(event, '";
  foundHelper = helpers.accId;
  stack1 = foundHelper || depth0.accId;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "accId", { hash: {} }); }
  buffer += escapeExpression(stack1) + "_";
  foundHelper = helpers.errorcode;
  stack1 = foundHelper || depth0.errorcode;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "errorcode", { hash: {} }); }
  buffer += escapeExpression(stack1) + "_";
  foundHelper = helpers.url;
  stack1 = foundHelper || depth0.url;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "url", { hash: {} }); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "_";
  foundHelper = helpers.accName;
  stack1 = foundHelper || depth0.accName;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "accName", { hash: {} }); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "_";
  foundHelper = helpers.accSiteAccountId;
  stack1 = foundHelper || depth0.accSiteAccountId;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "accSiteAccountId", { hash: {} }); }
  buffer += escapeExpression(stack1) + "');}\" onclick=\"yo.showAccountAlerts(event, '";
  foundHelper = helpers.accId;
  stack1 = foundHelper || depth0.accId;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "accId", { hash: {} }); }
  buffer += escapeExpression(stack1) + "_";
  foundHelper = helpers.errorcode;
  stack1 = foundHelper || depth0.errorcode;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "errorcode", { hash: {} }); }
  buffer += escapeExpression(stack1) + "_";
  foundHelper = helpers.url;
  stack1 = foundHelper || depth0.url;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "url", { hash: {} }); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "_";
  foundHelper = helpers.accName;
  stack1 = foundHelper || depth0.accName;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "accName", { hash: {} }); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "');\">";
  foundHelper = helpers.errorIconSmall;
  stack1 = foundHelper || depth0.errorIconSmall;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "errorIconSmall", { hash: {} }); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "</span>";
  return buffer;}

  buffer += "<dl class=\"accordion\" style=\"margin-left:auto;margin-right:auto;left:0;right:0\" >\n	<dd class=\"accordion-navigation ";
  foundHelper = helpers.accError;
  stack1 = foundHelper || depth0.accError;
  tmp1 = self.program(1, program1, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  if(foundHelper && typeof stack1 === functionType) { stack1 = stack1.call(depth0, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack1, tmp1); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\" >\n		<a class=\"flex\" href=\"#panel";
  foundHelper = helpers.accId;
  stack1 = foundHelper || depth0.accId;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "accId", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" onclick=\"yo.showAccountDetails(event,'";
  foundHelper = helpers.accId;
  stack1 = foundHelper || depth0.accId;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "accId", { hash: {} }); }
  buffer += escapeExpression(stack1) + "');\" onkeyup=\"if(yo.enter(event)){yo.showAccountDetails(event,'";
  foundHelper = helpers.accId;
  stack1 = foundHelper || depth0.accId;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "accId", { hash: {} }); }
  buffer += escapeExpression(stack1) + "');}\">\n			<div class=\"left\" style=\"width:100%;\">\n				<div class=\"left full-mobile\">\n					";
  foundHelper = helpers.modeName;
  stack1 = foundHelper || depth0.modeName;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "modeName", { hash: {} }); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "<div class=\"leftSide ";
  foundHelper = helpers.marginLeft;
  stack1 = foundHelper || depth0.marginLeft;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "marginLeft", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" title=\"";
  foundHelper = helpers.nameTxt;
  stack1 = foundHelper || depth0.nameTxt;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "nameTxt", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\">";
  foundHelper = helpers.accName;
  stack1 = foundHelper || depth0.accName;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "accName", { hash: {} }); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "</div>\n				</div>\n				<div class=\"left full-mobile\">\n					<div class=\"";
  foundHelper = helpers.modeSpacer;
  stack1 = foundHelper || depth0.modeSpacer;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "modeSpacer", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\">&nbsp;</div>\n					<div class=\"left-account-small\">";
  foundHelper = helpers.accType;
  stack1 = foundHelper || depth0.accType;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "accType", { hash: {} }); }
  buffer += escapeExpression(stack1) + " ";
  foundHelper = helpers.accDdescription;
  stack1 = foundHelper || depth0.accDdescription;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "accDdescription", { hash: {} }); }
  buffer += escapeExpression(stack1) + "</div>\n					<div class=\"left-account-small\">\n					<div class=\"accountIconsSmall\">\n						";
  foundHelper = helpers.switchEnableAccountSettings;
  stack1 = foundHelper || depth0.switchEnableAccountSettings;
  tmp1 = self.program(3, program3, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  if(foundHelper && typeof stack1 === functionType) { stack1 = stack1.call(depth0, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack1, tmp1); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n						";
  foundHelper = helpers.switchEnableAccountErrors;
  stack1 = foundHelper || depth0.switchEnableAccountErrors;
  tmp1 = self.program(6, program6, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  if(foundHelper && typeof stack1 === functionType) { stack1 = stack1.call(depth0, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack1, tmp1); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n						<span tabindex=\"0\" role=\"button\" title=\"";
  stack1 = "Press enter to refresh";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + " ";
  stack1 = "this Account";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\" class=\"refresh-btn ";
  foundHelper = helpers.hideOnHeld;
  stack1 = foundHelper || depth0.hideOnHeld;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "hideOnHeld", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" onclick=\"yo.AC.refresh(this,event);\" onkeyup=\"if(yo.enter(event)){yo.AC.refresh(this,event);}\"\n						 accountid=\"";
  foundHelper = helpers.accId;
  stack1 = foundHelper || depth0.accId;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "accId", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" name=\"";
  foundHelper = helpers.accName;
  stack1 = foundHelper || depth0.accName;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "accName", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" refreshType=\"";
  foundHelper = helpers.accRefreshType;
  stack1 = foundHelper || depth0.accRefreshType;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "accRefreshType", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" refreshMode=\"";
  foundHelper = helpers.accRefreshMode;
  stack1 = foundHelper || depth0.accRefreshMode;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "accRefreshMode", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" siteId=\"";
  foundHelper = helpers.accSiteId;
  stack1 = foundHelper || depth0.accSiteId;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "accSiteId", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" siteAccId=\"";
  foundHelper = helpers.accSiteAccountId;
  stack1 = foundHelper || depth0.accSiteAccountId;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "accSiteAccountId", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\">";
  foundHelper = helpers.showrefreshIcon;
  stack1 = foundHelper || depth0.showrefreshIcon;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "showrefreshIcon", { hash: {} }); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "<img src=\"";
  foundHelper = helpers.getRefreshImageUrl;
  stack1 = foundHelper || depth0.getRefreshImageUrl;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "getRefreshImageUrl", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" class=\"loader\"/></span>\n						<span class=\"";
  foundHelper = helpers.hideOnHeld;
  stack1 = foundHelper || depth0.hideOnHeld;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "hideOnHeld", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\"> ";
  stack1 = "Updated";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + " ";
  foundHelper = helpers.time;
  stack1 = foundHelper || depth0.time;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "time", { hash: {} }); }
  buffer += escapeExpression(stack1) + "</span>\n					</div>\n					</div>\n				</div>\n				<div class=\"right\">\n						<span class=\"";
  foundHelper = helpers.moneyColor;
  stack1 = foundHelper || depth0.moneyColor;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "moneyColor", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\">";
  foundHelper = helpers.amount1;
  stack1 = foundHelper || depth0.amount1;
  foundHelper = helpers.amount0;
  stack2 = foundHelper || depth0.amount0;
  foundHelper = helpers.money;
  stack3 = foundHelper || depth0.money;
  if(typeof stack3 === functionType) { stack1 = stack3.call(depth0, stack2, stack1, { hash: {} }); }
  else if(stack3=== undef) { stack1 = helperMissing.call(depth0, "money", stack2, stack1, { hash: {} }); }
  else { stack1 = stack3; }
  buffer += escapeExpression(stack1);
  foundHelper = helpers.moneyMarker;
  stack1 = foundHelper || depth0.moneyMarker;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "moneyMarker", { hash: {} }); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "</span>\n						<span tabindex=\"0\" role=\"button\" title=\"";
  stack1 = "Press enter to open";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + " ";
  stack1 = "Account Details Dialog";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\" class=\"plusIcon\">";
  foundHelper = helpers.plusIcon;
  stack1 = foundHelper || depth0.plusIcon;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "plusIcon", { hash: {} }); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "</span>\n				</div>\n			</div>\n		</a>\n		<div id=\"panel";
  foundHelper = helpers.accId;
  stack1 = foundHelper || depth0.accId;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "accId", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" class=\"content\">\n	    </div>\n	</dd>\n</dl>";
  return buffer;});
return templates;
});
/**
 * this view is responsible for showing single account details and transactions associated with the account.
 */
define('10003403_js/views/AccountDetailsView',['10003403_js/models/AccountsModel','10003403_js/compiled/finappCompiled'],function(AccountsModel,templates){
    var AccountDetailsView = Backbone.Marionette.ItemView.extend({
            
    	self:this,
    	tagName:'div',
    	template: templates['AccountDetails'],
    	
    	initialize : function(options) {
    		//console.log(this.model +'%%%%%%'+options.model);
    	},
    	
    	events :{
    		'click .leftArrow': 'hideAccountDetails',
    		'click .acctSettingslink': 'showAccountSettings',
    	},
    	
    	onRender: function(){
    		var containerType = this.model.get('type');
    		// on account details page show transactions module only for bank/card/investment containers
    		if(containerType && containerType.match(/^(BANK|Banking)$/) || containerType.match(/^(CREDITS|Credit Cards)$/) || containerType.match(/^(STOCKS|Investments)$/)) {
	    		var filter = new yo.TransactionFilter();
				filter.set({acctGroupId: this.model.get('id')+'_'+containerType.toLowerCase(),mode:'account'});// load transaction module // acct id shoulbe passed as 12567981_13013019_bank // 14101351_32152831_credits
				var txnContainer = this.$('.accountTxn');
				this.txnContainerRegion = new Backbone.Marionette.Region({
										  el: txnContainer
							});
	    		// render in expected div on this.template
	    		Application.Appcore.loadModule({ mode:filter, moduleKey : "10003204_10003507", moduleId : '10003507', el:'.accountTxn', region :this.txnContainerRegion});
	    	 }	
    		this.$('.leftArrow').html( ((yo.IE==8)?'<i class="i-z0019up_arrow"></i>':params.svg.leftArrowWhite));
    		
    	},
    	
    	templateHelpers : {
              accountName: function(){
                return this.name; // this refers to the model
              },
              amount0 :function(){ //this is because we are using money helper in template, hence we get access to yo.self
              	return yo.self.amount[0];
              },
              amount1 :function(){
              	return yo.self.amount[1];
              },
              id :function(){
              	return this.id;
              },
              switchEnableAccountSettings: function () {
                return yo.truth(params.switchEnableAccountSettings);
              },
              showAccountSettingsLink:function(){ // valid types: Bank, Bills, Credit, Rewards; otherwise show nothing
                var acctType = this['type'];
                var result = acctType.match(/^(BANK|Banking|CREDITS|Credit Cards|REWARD_PROGRAM|MILES|Rewards|Miles|BILLS|CABLE_SATELLITE|TELEPHONE|Cable &amp; Satellite|Phone &amp; Long Distance)$/);
                return result !== null; // valid types matches found -> result not null -> return true, otherwise false
              }
       },
       showAccountSettings: function(e){
       		$('body').removeClass("hideChildren");
       		yo.showAccountSettings(e,this.model.get('id'));
       },
       hideAccountDetails : function(){
	       yo.NG.hideSearchContainers();
	       $('body').removeClass("hideChildren");
	       this.close();
       },
       close : function(){
       		//release the dom and memory
       		this.txnContainerRegion.reset();
       		this.remove();
       }
    });
    return AccountDetailsView;
});

//sample accounts data production
/*{"results":[{"name":"Banking","containerName":"BANK","accounts":[{"id":"13946189_undefined","shareeAccountInfo":"","siteAccountId":"11329914","siteId":"2852","name":"Bank of America - Bank","contentServiceId":"2931","image":"https://personal.yodlee.com/apps/imagecache.personal.do?sum_info_id=2931&amp;icon=favicon","csid":"2931","homeUrl":"https://sitekey.bankofamerica.com/sas/signonScreen.do?state=NY","siteName":"Bank of America - Bank","modified":"2011-07-27T14:32:56.000-07:00","lastUpdate":"3 years ago","errorCode":"402","error":true,"isMan":false,"refreshType":"EDIT_SITE","refreshMode":"MFA","networthTypeId":"0","isNetIncl":false,"propertyId":null,"amount":[{"@":{"xmlns:xsi":"http://www.w3.org/2001/XMLSchema-instance","xsi:nil":"true"}},{"@":{"xmlns:xsi":"http://www.w3.org/2001/XMLSchema-instance","xsi:nil":"true"}}]},{"id":"13946188_undefined","shareeAccountInfo":"","siteAccountId":"11329914","siteId":"2852","name":"Bank of America - Bank","contentServiceId":"2931","image":"https://personal.yodlee.com/apps/imagecache.personal.do?sum_info_id=2931&amp;icon=favicon","csid":"2931","homeUrl":"https://sitekey.bankofamerica.com/sas/signonScreen.do?state=NY","siteName":"Bank of America - Bank","modified":"2011-07-27T14:28:56.000-07:00","lastUpdate":"3 years ago","errorCode":"402","error":true,"isMan":false,"refreshType":"EDIT_SITE","refreshMode":"MFA","networthTypeId":"0","isNetIncl":false,"propertyId":null,"amount":[{"@":{"xmlns:xsi":"http://www.w3.org/2001/XMLSchema-instance","xsi:nil":"true"}},{"@":{"xmlns:xsi":"http://www.w3.org/2001/XMLSchema-instance","xsi:nil":"true"}}]},{"id":"14796581_undefined","shareeAccountInfo":"","siteAccountId":"11006861","siteId":"16487","name":"Dag Site (no account summary) - Bank","contentServiceId":"20642","image":"https://personal.yodlee.com/apps/imagecache.personal.do?sum_info_id=20642&amp;icon=favicon","csid":"20642","homeUrl":"http://abc.com/loginurl","siteName":"Dag Site (no account summary) - Bank","modified":"2013-03-12T13:09:50.000-07:00","lastUpdate":"1 year ago","errorCode":"402","error":true,"isMan":false,"refreshType":"EDIT_SITE","refreshMode":"NORMAL","networthTypeId":"0","isNetIncl":false,"propertyId":null,"amount":[{"@":{"xmlns:xsi":"http://www.w3.org/2001/XMLSchema-instance","xsi:nil":"true"}},{"@":{"xmlns:xsi":"http://www.w3.org/2001/XMLSchema-instance","xsi:nil":"true"}}]},{"id":"14377468_undefined","shareeAccountInfo":"","siteAccountId":"11329919","siteId":"8995","name":"DagBank","contentServiceId":"11195","image":"https://personal.yodlee.com/apps/imagecache.personal.do?sum_info_id=11195&amp;icon=favicon","csid":"11195","homeUrl":"http://dag2.yodlee.com/dag/index.do","siteName":"DagBank","modified":"2012-03-01T10:45:52.000-08:00","lastUpdate":"2 years ago","errorCode":"402","error":true,"isMan":false,"refreshType":"EDIT_SITE","refreshMode":"NORMAL","networthTypeId":"0","isNetIncl":false,"propertyId":null,"amount":[{"@":{"xmlns:xsi":"http://www.w3.org/2001/XMLSchema-instance","xsi:nil":"true"}},{"@":{"xmlns:xsi":"http://www.w3.org/2001/XMLSchema-instance","xsi:nil":"true"}}]}],"total":["0.0","USD"]},{"name":"BILLS","containerName":"BILLS","accounts":[{"id":"12954859_30944166","shareeAccountInfo":"","siteAccountId":"11329916","siteId":"4329","name":"AT&amp;T - Bills - xxxx 915","description":"xxxxx915","contentServiceId":"4942","image":"https://personal.yodlee.com/apps/imagecache.personal.do?sum_info_id=4942&amp;icon=favicon","csid":"4942","homeUrl":"http://www.att.com/","siteName":"AT&amp;T - Bills","modified":"2011-02-11T12:00:08.000-08:00","type":"unknown","lastUpdate":"3 years ago","errorCode":"402","error":true,"isMan":false,"refreshType":"EDIT_SITE","refreshMode":"NORMAL","networthTypeId":"0","isNetIncl":"true","propertyId":null,"amount":[{"@":{"xmlns:xsi":"http://www.w3.org/2001/XMLSchema-instance","xsi:nil":"true"}},{"@":{"xmlns:xsi":"http://www.w3.org/2001/XMLSchema-instance","xsi:nil":"true"}}]}],"total":["0.0","USD"]},{"name":"Cable &amp; Satellite","containerName":"CABLE_SATELLITE","accounts":[{"id":"14581256_32670565","shareeAccountInfo":"","siteAccountId":"11329917","siteId":"7694","name":"Comcast - Bills","description":"xxxx5687","contentServiceId":"9832","image":"https://personal.yodlee.com/apps/imagecache.personal.do?sum_info_id=9832&amp;icon=favicon","csid":"9832","homeUrl":"https://login.comcast.net/login?forceAuthn=1&amp;continue=%2fSecure%2fHome.aspx&amp;s=ccentral-cima&amp;r=comcast.net","siteName":"Comcast - Bills","modified":"2013-05-21T14:05:09.000-07:00","type":"unknown","lastUpdate":"1 year ago","errorCode":"402","error":true,"isMan":false,"refreshType":"EDIT_SITE","refreshMode":"NORMAL","networthTypeId":"0","isNetIncl":"true","propertyId":null,"amount":["91.94","USD"]}],"total":["91.94","USD"]},{"name":"Cell Phone &amp; Wireless","containerName":"MINUTES","accounts":[{"id":"12933128_30920291","shareeAccountInfo":"","siteAccountId":"11329907","siteId":"2","name":"Sprint PCS - Bills","description":"xxxx0899","contentServiceId":"2","image":"https://personal.yodlee.com/apps/imagecache.personal.do?sum_info_id=2&amp;icon=favicon","csid":"2","homeUrl":"http://www.sprint.com/mysprint/pages/sl/global/index.jsp","siteName":"Sprint PCS - Bills","modified":"2013-01-10T15:34:10.000-08:00","type":"unknown","lastUpdate":"1 year ago","errorCode":"5","error":true,"isMan":false,"refreshType":"NOT_REFRESHABLE","refreshMode":"MFA","networthTypeId":"0","isNetIncl":"true","propertyId":null,"amount":["0.0","USD"]}],"total":["0.0","USD"]},{"name":"Credit Cards","containerName":"CREDITS","accounts":[{"id":"13794632_undefined","shareeAccountInfo":"","siteAccountId":"11329911","siteId":"12","name":"American Express Cards","contentServiceId":"12","image":"https://personal.yodlee.com/apps/imagecache.personal.do?sum_info_id=12&amp;icon=favicon","csid":"12","homeUrl":"https://online.americanexpress.com/myca/acctsumm/us/action?request_type=authreg_acctAccountSummary&amp;entry_point=yodlee","siteName":"American Express Cards","modified":"2011-04-25T15:14:01.000-07:00","lastUpdate":"3 years ago","errorCode":"402","error":true,"isMan":false,"refreshType":"EDIT_SITE","refreshMode":"MFA","networthTypeId":"0","isNetIncl":false,"propertyId":null,"amount":[{"@":{"xmlns:xsi":"http://www.w3.org/2001/XMLSchema-instance","xsi:nil":"true"}},{"@":{"xmlns:xsi":"http://www.w3.org/2001/XMLSchema-instance","xsi:nil":"true"}}]},{"id":"13794633_undefined","shareeAccountInfo":"","siteAccountId":"11329909","siteId":"12","name":"American Express Cards","contentServiceId":"12","image":"https://personal.yodlee.com/apps/imagecache.personal.do?sum_info_id=12&amp;icon=favicon","csid":"12","homeUrl":"https://online.americanexpress.com/myca/acctsumm/us/action?request_type=authreg_acctAccountSummary&amp;entry_point=yodlee","siteName":"American Express Cards","modified":"2011-04-25T15:15:58.000-07:00","lastUpdate":"3 years ago","errorCode":"402","error":true,"isMan":false,"refreshType":"EDIT_SITE","refreshMode":"MFA","networthTypeId":"0","isNetIncl":false,"propertyId":null,"amount":[{"@":{"xmlns:xsi":"http://www.w3.org/2001/XMLSchema-instance","xsi:nil":"true"}},{"@":{"xmlns:xsi":"http://www.w3.org/2001/XMLSchema-instance","xsi:nil":"true"}}]},{"id":"13794631_undefined","shareeAccountInfo":"","siteAccountId":"11329910","siteId":"12","name":"American Express Cards","contentServiceId":"12","image":"https://personal.yodlee.com/apps/imagecache.personal.do?sum_info_id=12&amp;icon=favicon","csid":"12","homeUrl":"https://online.americanexpress.com/myca/acctsumm/us/action?request_type=authreg_acctAccountSummary&amp;entry_point=yodlee","siteName":"American Express Cards","modified":"2011-04-25T15:13:01.000-07:00","lastUpdate":"3 years ago","errorCode":"402","error":true,"isMan":false,"refreshType":"EDIT_SITE","refreshMode":"MFA","networthTypeId":"0","isNetIncl":false,"propertyId":null,"amount":[{"@":{"xmlns:xsi":"http://www.w3.org/2001/XMLSchema-instance","xsi:nil":"true"}},{"@":{"xmlns:xsi":"http://www.w3.org/2001/XMLSchema-instance","xsi:nil":"true"}}]}],"total":["0.0","USD"]},{"name":"Investments","containerName":"STOCKS","accounts":[{"id":"14657246_undefined","shareeAccountInfo":"","siteAccountId":"11329923","siteId":"16441","name":"Dag Site - Investments","contentServiceId":"20549","image":"https://personal.yodlee.com/apps/imagecache.personal.do?sum_info_id=20549&amp;icon=favicon","csid":"20549","homeUrl":"http://192.168.210.152:9090/dag/index.do","siteName":"Dag Site - Investments","modified":"2012-12-26T23:13:05.000-08:00","lastUpdate":"1 year ago","errorCode":"402","error":true,"isMan":false,"scrapedTotalBalanceUsed":"false","refreshType":"EDIT_SITE","refreshMode":"NORMAL","networthTypeId":"0","isNetIncl":false,"propertyId":null,"amount":[{"@":{"xmlns:xsi":"http://www.w3.org/2001/XMLSchema-instance","xsi:nil":"true"}},{"@":{"xmlns:xsi":"http://www.w3.org/2001/XMLSchema-instance","xsi:nil":"true"}}]}],"total":["0.0","USD"]},{"name":"Other Accounts","containerName":"OTHER","accounts":[{"siteAccountId":"11329918","siteId":"8920","name":"Gmail","errorCode":"402","error":true,"refreshType":"EDIT_SITE","refreshMode":"NORMAL","siteUrl":"https://gmail.google.com/","partialSite":true}]},{"name":"Real Estate","containerName":"REALESTATE","accounts":[{"id":"13947446_32065958","shareeAccountInfo":"","siteAccountId":"11329921","siteId":"10642","name":"Home Value (Zestimate&lt;sup&gt;®&lt;/sup&gt;) - Home","contentServiceId":"13059","image":"https://personal.yodlee.com/apps/imagecache.personal.do?sum_info_id=13059&amp;icon=favicon","csid":"13059","homeUrl":"http://www.zillow.com/","siteName":"Home Value (Zestimate&lt;sup&gt;®&lt;/sup&gt;)","modified":"2011-07-28T13:02:23.000-07:00","lastUpdate":"3 years ago","errorCode":"510","error":true,"isMan":false,"refreshType":"NOT_REFRESHABLE","refreshMode":"NORMAL","networthTypeId":"1","isNetIncl":"true","propertyId":"2130757975","amount":["531000.0","USD"]}],"total":["531000.0","USD"]}]}*/
;
/**
 * this view is responsible for showing single account settings, controls and apis to change account settings
 */
define('10003403_js/views/AccountSettingsView',['10003403_js/models/AccountsModel','10003403_js/compiled/finappCompiled'],function(AccountsModel,templates){
    var AccountSettingsView = Backbone.Marionette.ItemView.extend({
            
    	//region: '#accounts',
    	self:this,
    	
    	template: templates['AccountSettings'],
    	
    	initialize : function(options) {
    		this.containerType = options.containerType;
    	},
    	events :{
    		'click .leftArrow': 'hideAccountDetails',
    		'click .acctDetailslink': 'showAccountDetails',
        'click .adjustRangeBtnPlus': 'updateAdjusterRange',
        'click .adjustRangeBtnMinus': 'updateAdjusterRange',
        'click .switch': 'handleSettingSwitch',
        'click .btnDeleteAccount': 'promptAccountRemoval',
        'click #execAccountDelete': 'executeAccountRemoval',
        'keydown input[type=tel]': 'inputFieldHandler',
        'keyup input[type=tel]': 'inputKeyupHandler',
        'blur input[type=tel]': 'inputBlurHandler',
    	},
    	
    	onRender: function(){
    		this.$('.leftArrow').html( ((yo.IE==8)?'<i class="i-z0019up_arrow"></i>':params.svg.leftArrowWhite));
    	},
    	templateHelpers : {

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
       inputBlurHandler: function(e) {
          var obj = e.currentTarget;
          var defaultValue = false;
          var limitMin = parseInt(obj.getAttribute('voidmin'));
          var limitMax = parseInt(obj.getAttribute('voidmax'));
          var number = parseInt(obj.value);
          if (isNaN(number) || number == 0) {
            defaultValue = true;
          } else if (!isNaN(limitMin) && number < limitMin) {
            number = limitMin;
          } else if (!isNaN(limitMax) && number > limitMax) {
            number = limitMax;
          }
          console.log(obj.value);
          obj.value = defaultValue ? obj.getAttribute('voidvalue') : number;
          console.log(obj.value + " <<< finalized");
       },
       inputFieldHandler: function(e) {
          var obj = e.currentTarget;
          var key = e.keyCode ? e.keyCode : e.which;
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
          if (!e.shiftKey && !isNaN(number)) {
            return true;
          }
          // else if all fails then false exit which will dismiss keypress
          e.preventDefault();
          return false;

       },
        inputKeyupHandler: function(e) {
          var obj = e.currentTarget;
          var limitMax = parseInt(obj.getAttribute('voidmax'));
          // prevent user input greater than $limitMax
          if (!isNaN(limitMax) && obj.value > limitMax) {
            obj.value = limitMax;
          }
        },
       handleSettingSwitch: function(e){
          var checkbox = $(e.currentTarget).find("input[type=checkbox]").get(0);
          var targetDiv = $("#" + checkbox.id + "_Target");
          var targetInput = targetDiv.find("input[type=tel]").get(0);
          if (!checkbox || !targetDiv || !targetInput) {
            return; // exit on error
          }
          if (checkbox.checked) {
            checkbox.checked = false;
            targetInput.disabled = true;
            // if (! $(target).hasClass("settingInactive")) {
            targetDiv.addClass("settingInactive");
            // }
          } else {
            checkbox.checked = true;
            targetInput.disabled = false;
            // if ($(target).hasClass("settingInactive")) {
            targetDiv.removeClass("settingInactive");
            // }
          }
       },
       updateAdjusterRange: function(e){
          var rangeInputElement = $(e.currentTarget).parents(".adjustRange").find("input.adjustRangeVal").get(0);
          var stateInactive = $(e.currentTarget).parents(".settingAdjusters").hasClass("settingInactive");
          var increment = $(e.currentTarget).attr("updaterange");
          var rangeMin = parseInt(rangeInputElement.getAttribute('voidmin')), 
              rangeMax = parseInt(rangeInputElement.getAttribute('voidmax')), 
              rangeValueInitial = rangeValueFinal = parseInt(rangeInputElement.value);

          if (stateInactive) return;
          else if (increment == "up") rangeValueFinal += 1;
          else if (increment == "down") rangeValueFinal -= 1;
          else return;

          if (rangeValueFinal >= rangeMin && rangeValueFinal <= rangeMax) rangeInputElement.value = rangeValueFinal;
       },
       promptAccountRemoval: function(e) {
        var obj = e.currentTarget;
        var removeAcctId = obj.getAttribute('removeAcctId');
        overlay.modalShow({
          'new':true,
          'default':true,
          'hookNode': obj.parentNode,
          'addClass': 'promptConfirmation global-modal', 
          'addContent': "<h5>Are you sure you want to delete this account from Timely?</h5>" + 
                        "<div class='clearfix'>" +
                          "<a class='button ofSameSize warning left'    href='#' id='execAccountDelete' removeAcctId='" + removeAcctId + "'>Delete</a>" +
                          "<a class='button ofSameSize secondary right' href='javascript:overlay.hide()'>Cancel</a>" + 
                        "</div>"
        });
       },
       executeAccountRemoval: function(e) {
        var obj = e.currentTarget;
        var removeAcctId = obj.getAttribute('removeAcctId');
        overlay.hideAll(); // remove confirmation prompt overlays
        this.hideAccountDetails(); // remove account settings overlay
        // line below emulates api call for acct removal
        console.log("Perform removal of account # " + removeAcctId + ".");
        // update ui
        
        var removalNode = $('#panel'+removeAcctId).parents('.accordion').get(0);
        if (!removalNode) return;
        removalNode.setAttribute("class", removalNode.className + " itemDeleted");
        // perform actual removal
        setTimeout(function () {
          removalNode.parentNode.removeChild(removalNode);
        }, 500);
       },
       showAccountDetails: function(e){
       	/* optimize this*/
       		yo.showAccountDetails(e,this.model.get('id'));
       },
       hideAccountDetails : function(){
	       yo.NG.hideSearchContainers();
	       this.close();
       },
       close : function(){
       		//release the dom and memory
       		this.remove();
       }
    });
    return AccountSettingsView;
});



define('10003403_js/views/AccountRowView',['10003403_js/collections/AccountsCollection','10003403_js/models/AccountsModel','10003403_js/views/AccountDetailsView','10003403_js/views/AccountSettingsView','10003403_js/compiled/finappCompiled'],function(AccountsCollection,AccountsModel,AccountDetailsView,AccountSettingsView,templates){
    var AccountView = Backbone.Marionette.ItemView.extend({
    	
    	region: yo.accountsRegion || '.detailAccountList',
        
    	self:this,
    	
    	template: templates['AccountsRow'],
    	
    	initialize : function() {
    	    self.collection =[];
    		// Init accounts
    		if( PARAM.accountData && PARAM.accountData.obj) {
    		  self.collection = new AccountsCollection(PARAM.accountData.obj.results? PARAM.accountData.obj.results: [] );
    		}  
    		
    	},
    	renderView :function(){
    		
    		this._ensureViewIsIntact();
    		var template = this.getTemplate();
    		var mainData = this.serializeData(),i,j,k,m;
	      	subData = this.mixinTemplateHelpers(mainData);
	      	yo.doAccountClick = function(event){
				var e = event;
				yo.endEvt(e);
				
				$('#accounts-overlay').removeClass('hide');
			};
	  		return this;
    	},
    	templateHelpers : {
			nameTxt:function(){
				return this.name;
			},
			accName: function(){
			  	return this.name;
			},
			modeName: function(){
				if(yo.accountDisplayMode!='fi'){
					return yo.accountFavicon;
				}
				return '';
			},
			modeSpacer:function(){
				if(yo.accountDisplayMode=='fi'){
					return "hide";
				}
				return "spacer";
			},
			marginLeft:function(){
				if(yo.accountDisplayMode!='fi'){
					return 'margin-left';
				}
				return '';
			},
            amount0 :function(){
              	return yo.self.amount[0];
            },
            amount1 :function(){
              	return yo.self.amount[1];
            },
            accId :function(){
				return this.id;
            },
            moneyColor:function(){
              	var type = this.type;
              	if(this.amount[0]>=0&&type!="Bills"&&type !="Credit Cards"&&type!="Loans"&&type!="Mortgages"&&type!="Other Liabilities"&&type!="Phone & Long Distance"&&type!="Utilities"){
              		return "green";
              	}
              	return "";
            },
            moneyMarker:function(){
              	if(yo.realEstateThisAccount){
              		return "<sup>‡</sup>";
              	}return "";
            },
            time: function(){
              	var lastUpdated;
              	if(this.lastUpdate){
					lastUpdated = this.lastUpdate;
					if(PARAM.prefs.locale!='en_US'){
						//translate it if not english
						
						var parseString = lastUpdated.split(' ')
						,m;
						lastUpdated='';
						
						for(m=0;m<parseString.length;m++){
							if(isNaN(parseString[m])&&typeof(PARAM.calLangHash[parseString[m]])!="undefined"){
								lastUpdated+=PARAM.calLangHash[parseString[m]];
							}else{
								lastUpdated+=parseString[m];
							}
							if(m+1<parseString.length)lastUpdated+=' ';
						}
					}
				}else{
					lastUpdated = yo.diffDates(this.modified, new Date(), 1);
				}
				return lastUpdated;
           },
           accType:function(){
             	if(this.type=="BILLS"||this.type=="INSURANCE"){
             		return __[this.type.substring(0,1)+this.type.substring(1).toLowerCase()];
             	}
             	if(this.type=="Cable &amp; Satellite"){
             		return __["Cable & Satellite"];
             	}
             	if(this.type=="Phone &amp; Long Distance"){
             		return __["Phone & Long Distance"];
             	}
             	return __[this.type];
           },
           accDdescription:function(){
             	if(this.description){
             		return '| '+this.description;
             	}
             	return '';
           },// data-refreshtype="'+accounts[j].refreshType+'" data-refreshmode="'+accounts[j].refreshMode+'" data-siteid="'+accounts[j].siteId+'" data-siteaccid="'+accounts[j].siteAccountId+'"
           accRefreshType:function(){
             	return this.refreshType;
           },
           accRefreshMode:function(){
             	return this.refreshMode;
           },
           errorIconSmall:function(){
              	return params.svg.errorIconSmall+'<i class="i-alert"></i>';
           },
           accError: function() {
           	return this.error;
           },
           errorcode:function(){
              	return this.errorCode;
           },
           url:function(){
           		var url = ( this.homeUrl && this.homeUrl.length > 0 && this.homeUrl != this.csid && this.homeUrl != 'undefined' ) ? this.homeUrl : 'NA';
                //handle url for partialsites
                url=this['partialSite'] ? this['siteUrl']:url;
           		return url;
           },
           accSiteId:function(){
           return this.siteId;
           },
           accSiteAccountId:function(){
             	return this.siteAccountId;
           },
           hideOnHeld:function(){
             	if(this.isHeld=="true")return "hide";
             	return '';
           },
           switchEnableAccountErrors: function(){
           	return yo.truth(params.switchEnableAccountErrors);
           },
			switchEnableAccountSettings: function () {
				return yo.truth(params.switchEnableAccountSettings);
			},
			showAccountSettingsIcon:function(){
				return params.svg.settings+'<i class="i-settings"></i>';
			},
			showAccountSettingsLink:function(){ // valid types: Bank, Bills, Credit, Rewards; otherwise show nothing
				var acctType = this.type;
				var result = acctType.match(/^(BANK|Banking|CREDITS|Credit Cards|REWARD_PROGRAM|MILES|Rewards|Miles|BILLS|CABLE_SATELLITE|TELEPHONE|Cable &amp; Satellite|Phone &amp; Long Distance)$/);
				return result !== null; // valid types matches found -> result not null -> return true, otherwise false
				
			},
			showrefreshIcon:function(){
				return params.svg.refreshIcon+'<i class="i-refresh"></i>';
			},
           cancelIcon: function(){
	            return params.svg.cancelIcon+'<i class="i-cancel"></i>'; // this refers to the model//if there is no extra helper, just use this, otherwise use yo.self
	       },
	       getRefreshImageUrl: function() {
	       	if(PARAM.isMobile) {
	       		return 'img/loader.gif';
	       	} else {
	       		return '/img/loader.gif';
	       	}
	       },
       		plusIcon:function(){
       			return params.svg.plusIcon+'<i class="i-z0024plus"></i>';
       		}
        }
    });
    return AccountView;
});



define('10003403_js/views/AccountsView',['10003403_js/collections/AccountsCollection','10003403_js/models/AccountsModel','10003403_js/views/AccountDetailsView','10003403_js/views/AccountSettingsView','10003403_js/views/AccountRowView','10003403_js/compiled/finappCompiled'],function(AccountsCollection,AccountsModel,AccountDetailsView,AccountSettingsView,AccountView,templates){
    var AccountsView = Backbone.Marionette.ItemView.extend({
    	
    	region: yo.accountsRegion || '#body-content-js',
        
    	self:this,
    	
    	template: templates['AccountsList'],
    	initialize : function() {
    	    self.collection =[];
    		// Init accounts
    		
    		if( PARAM.accountData && PARAM.accountData.obj) {
    		  self.collection = new AccountsCollection(PARAM.accountData.obj.results? PARAM.accountData.obj.results: [] );
    		}
    	},
    	// need to clean up the acct details view when close X is clicked (desktop version only)
    	// ui: {
			// closeIcon: '#desktopSearchCancel'
		// },
		 events: {
		   // 'click .errorAccounts': 'showErrorAccounts',
		    'click #refresh' : 'refreshAccount'
		   },
    	refreshAccount: function(event){
    		yo.AC.refresh(this,event);
    	},
    	renderView :function() {
    		var template = this.getTemplate();
    		yo.accountDisplayMode=='fi';
    		var html='',subTitle='<div class="sub-title-light top">';
    		var accountErrorModel = [];
    		var mainData = this.serializeData(),i,j,k,m;
	      	subData = this.mixinTemplateHelpers(mainData);
	      	yo.showAccountAlerts =  function(e, errorid){
				yo.endEvt(e);
				
				var accountid = errorid.split('_')[0]+'_'+errorid.split('_')[1]
				, errorNum = errorid.split('_')[2]
				, url = errorid.split('_')[3]
				, name = errorid.split('_')[4]
				, errorMsg = __["error_"+errorNum+"_title"]
				, errorSubMsg = __["error_"+errorNum+"_desc"]//for some reason the code is changing this to desc from description inside Timely, not sure if this would happen in Fast Link too, might be Kishore's code'
				, btn1ADA = __[errorNum+"_btn1"]
				, btn1Name = __[errorNum+"_btn1"]
				, btn1Class
				, btn1Func
				, btn2ADA = __[errorNum+'_btn2']
				, btn2Name = __[errorNum+'_btn2']
				, btn2Class
				, btn2Func;
				
				yo.idStored = accountid;
				yo.siteAccountIdStored = errorid.split('_')[5];
				if(btn1Name==__["VERIFY CREDENTIALS"]||btn1Name==__["EDIT CREDENTIALS"]){
					if(btn2Name){
						btn1Class = " primary left";
					}else{
						btn1Class = " primary";
					}
					btn1Func = "yo.openFastLink('"+params.accountsModule+"');";
				}
				if(btn1Name==__["TRY AGAIN"]){
					btn1Class = " primary";
					if(url!="NA"){
						btn1Func = "window.open('"+url+"')";
						btn1Class = " secondary";//no sideby side since it is alone
					}else{
						btn1Class = "hide";
					}
				}
				if(btn1Name==__["DELETE ACCOUNT"]){
					btn1Func = 'yo.hideModalDialog(); yo.addModalDialog(yo.getModalDialogHtml({mainMsg:\''+__["Are you sure you want to delete this account?"]+" "+__["This cannot be undone."]+'\',btn1Class:\'warning deleteTagBtn ofSameSize\',btn1ADAMsg:\''+__["Delete"]+" "+__["Account"]+'\',btn1Msg:\''+__["Delete"]+'\',btn1Func:\'yo.deleteAccount()\',btn2Class:\'secondary cancelBtn ofSameSize\',btn2ADAMsg:\''+__["Cancel"]+'\',btn2Msg:\''+__["Cancel"]+'\',btn2Func:\'yo.hideModalDialog()\'}),yo.originator);';
					if(btn2Name){
						btn1Class = " warning left";
					}else{
						btn1Class = " warning";
					}
				}
				if(btn1Name==__["GO TO SITE"]){
					if(url!="NA"&&params.showGotoSiteLink){
						btn1Func = "window.open('"+url+"')";
						btn1Class = " secondary";//no sideby side since it is alone
					}else{
						btn1Class = "hide";
					}
				}
				if(btn2Name==__["GO TO SITE"]){
					if(url!="NA"&&params.showGotoSiteLink){
						btn2Func = "window.open('"+url+"')";
						btn2Class = " secondary sideBySide right";
					}else{
						btn2Class = " hide";
						btn1Class = " primary";//remove the left
					}
					
				}
				if(btn2Name==__["CANCEL"]){
					btn2Func = "yo.hideModalDialog()";
					btn2Class = " secondary sideBySide right";
				}
				
				errorMsg= errorMsg.replace(/_SITE_DISPLAY_NAME_/g,name);
				errorSubMsg= errorSubMsg.replace(/_SITE_DISPLAY_NAME_/g,name);
				
				yo.addModalDialog(yo.getModalDialogHtml({mainMsg:errorMsg,
				  subMsg:errorSubMsg,
                  btn1Class:btn1Class,
                  btn1ADAMsg:btn1ADA,
                  btn1Msg:btn1Name,
                  btn1Func:btn1Func,
                  btn2Class:btn2Class,
                  btn2ADAMsg:btn2ADA,
                  btn2Msg:btn2Name,
                  btn2Func:btn2Func}),e.target);

				return false;
			};
			/**
         * Actually calls the api to delete account - called when the user click the Delete Account button
         * id is the id of the acount we wish to delete
         *
         */
	        yo.deleteAccount =function(){
	            yo.hideModalDialog();
	            var deleteAccList,
	            filterString='filter[]=requestType,GET&filter[]=url,/v1.0/jsonsdk/';
	            if(yo.siteAccountIdStored && yo.siteAccountIdStored != "undefined"){
	                filterString += 'SiteAccountManagement/removeSiteAccount&jsonFilter={"memSiteAccId":"'+yo.siteAccountIdStored+'"}';
	            }else if(yo.idStored.indexOf('undefined')==-1){
	                filterString += 'ItemAccountManagement/removeItemAccount&jsonFilter={"itemAccountId":"'+yo.idStored.split('_')[1]+'"}';
	            }else{
	                filterString += 'ItemManagement/removeItem&jsonFilter={"itemId":"'+yo.idStored.split('_')[0]+'"}';
	            }
	            yo.api('/services/InternalPassThrough/makeCall/', function(data) {
	                yo.api('/services/Account/allGrouped/', function(data){
	                    PARAM.storedAccountData =data;
	                    PARAM.accountData = data;
	                    yo.NG.loadUserSettings();//reload User Settings completely
	                });
	            }, filterString);
	            
	        };
			/**
			 * function toggles filter by error accounts area to open and close and removes error accounts from the other areas
			 * @param {object}: event is window.event object
			 * 
			 */
			
		yo.toggleErrorAccounts  = function(event){
			yo.endEvt(event);
			
		     var $ele = $(event.currentTarget).parent();
		     $ele.find(".errorAccountsList").slideToggle( "slow", function() {
		     var setToHide = $ele.find(".detailAccountList .hasAccountError"),i;
		     if ($ele.find(".detailAccountList .hasAccountError").css('display') == 'none') {
		       $ele.find('.accountErrorArrow').html(params.svg.downArrowError);
		       for(i=0;i<setToHide.length;i++){
		       	$(setToHide[i].parentNode).show();
		       	$(setToHide[i].parentNode.previousSibling).show();
		       }
		       $($ele.context).attr("title",__["Press enter to open"]+' '+__["Accounts with errors"]);
		    }else {
		       $ele.find('.accountErrorArrow').html(params.svg.upArrowError);
		       for(i=0;i<setToHide.length;i++){
		       	$(setToHide[i].parentNode).hide();
		       	$(setToHide[i].parentNode.previousSibling).hide();
		       }
		       $($ele.context).attr("title",__["Press enter to close"]+' '+__["Accounts with errors"]);
		    }
		    $('.errorAccountsList').find('a')[0].focus();
 		 });
    	};
			yo.showAccountDetails = function(e, acctId){
				
	            yo.endEvt(e);
	            var elem = (e.target)?e.target:e.srcElement;
	            if( elem && elem.tagName == 'svg'){
	            	elem = elem.parentNode;
	            }
	            if(elem && elem.className && typeof elem.className === 'string' && elem.className.indexOf('refresh-btn') >= 0) {return;} // return if user clicked on refresh icon
	            console.log(acctId, ' details showing');
	            //find the account data for this acctId 
	            var singleAccount;
	            for(k=0;k<mainData.items.length;k++){
		  			var item = mainData.items[k];
	  				for(m=0;m<item.accounts.length;m++){
	  					if(item.accounts[m].id==acctId){
	  						singleAccount = item.accounts[m];
	  					}
		  			}
		  			
		  		}
				// create account data model
           	    var singleAccountModel = new AccountsModel(singleAccount);
           	    
           	    //create account details view
           	    var singleAccountView = new AccountDetailsView({model:singleAccountModel});
				
				self.activeDetailView = singleAccountView;
				//find the account details div on page and inject the view markup there 
				yo.NG.showSearch();
				$('#searchBoxContainer').hide();
				$('#advancedSearch').hide();
				$('#searchResults').html(singleAccountView.render().el);
				yo.activeContainer="searchResultsContainer";
				$('#searchResultsContainer').addClass('accountsOverlay');
				$('#searchResultsContainer')[0].focus();
				//yo.resize();
			};
			yo.showAccountSettings = function(event,acctId){
				yo.endEvt(event);
				if(!acctId) {
				    var acctId = $(event.currentTarget).data('accountid');
				}    
	            //find the account data for this acctId TODO: logic
	            var singleAccount;
	            for(k=0;k<mainData.items.length;k++){
		  			var item = mainData.items[k];
	  				for(m=0;m<item.accounts.length;m++){
	  					if(item.accounts[m].id==acctId){
	  						singleAccount = item.accounts[m];
	  					}
		  			}
		  			
		  		}
	            
				// create account data model
           	    var singleAccountModel = new AccountsModel(singleAccount);
           	    
           	    //create account settings view
           	    var singleAccountSettingsView = new AccountSettingsView({model:singleAccountModel});
				self.activeDetailView = singleAccountSettingsView;
				//find the account details div on page and inject the view markup there 
				// CR: changed to render acct details in search results container
				yo.NG.showSearch();
				$('#searchBoxContainer').hide();
				$('#advancedSearch').hide();
				$('#searchResults').html(singleAccountSettingsView.render().el);
				yo.activeContainer="searchResultsContainer";
				$('#searchResultsContainer').addClass('accountsOverlay');
				//yo.resize();
			};
			yo.getFavicon = function(item,j){
				var faviconUrl='';
				if ( params.showAccountFavicon === true ) {
					faviconUrl = item.accounts[j].image;
					if(item.accounts[j].partialSite) {
						faviconUrl = params.site_favicon_url+'&siteId='+item.accounts[j].siteId;
					}
					yo.accountFavicon = '<div class="icon"><img tabindex="0" height="15" width="15" alt="'+__['Icon']+'" title="'+__['Icon']+'" src="'+ faviconUrl +'"/></div>';
				} else {
					yo.accountFavicon = '<div class="svg-icon">'+params.svg[item.containerName]+'</div>';
				}
			};
	      if(yo.accountDisplayMode=='fi'){//financial institution mode
	      	var vs = $('#viewSelect a');
	      	if(vs.length) {
	  			vs[0].innerHTML = vs[0].innerHTML.replace(__["ACCOUNT TYPE"],__["FINANCIAL INSTITUTION"]).replace(__["ACCOUNT TYPE"],__["FINANCIAL INSTITUTION"]);
				}
	  			
				var name ='',faviconUrl,isFirst;
				for(h=0;h<2;h++){//h==0 is held accounts and h==1 is held away accounts, there is a requirement to show held accounts in a group at the top in this mode
					isFirst=true;
					if(h==1){
						html+='<div class="sub-title white clearfix">'+__["ADDITIONAL ACCOUNTS"]+'</div>';
					}
					
					for(i=0;i<mainData.items.length;i++){
						var nameitem = mainData.items[i];
						for(j=0;j<nameitem.accounts.length;j++){
							if(h==0&&nameitem.accounts[j].isHeld!="true"){
								continue;
							}else if(h==1&&nameitem.accounts[j].isHeld=="true"){
								continue;
							}
							name = nameitem.accounts[j].name;//name is name we 'filter' by
							
							yo.getFavicon(nameitem,j);
							
							if(h==0&&isFirst==true||h==1){
								var padTop='';
								if(!isFirst){
									padTop='margin-top';
								}
								html+='<div class="sub-title-light top '+padTop+'">'+yo.accountFavicon+'<span class="table-row">'+name+'</span></div>';
								isFirst=false;
							}
							for(k=0;k<mainData.items.length;k++){
					  			var item = mainData.items[k];
					  			if(item.containerName=="REALESTATE"){
			  						yo.realEstateFound=true;
			  						yo.realEstateThisAccount=true;
			  					}
			  					if(item.containerName=="REWARD_PROGRAM"||item.containerName=="MILES"){
			  						yo.rewardsAct=true;
			  					}
				  				for(m=0;m<item.accounts.length;m++){
				  					if(item.accounts[m].name==name){
				  						item.accounts[m].type = item.name;
				  						subData.account = item.accounts[m];
						  				// Render and add to el
						  				
						  var singleAccountModel = new AccountsModel(subData.account);
           	              var singleAccountView = new AccountView({model:singleAccountModel});
           	              if(subData.account.error){
           	              	accountErrorModel.push(subData.account);
           	              }
				          html += singleAccountView.render().el.innerHTML;
								      	//html += Marionette.Renderer.render(accountTemplate, subData, this);
								      	
				  					}
					  			}
					  			yo.rewardsAct=false;
					  			yo.realEstateThisAccount=false;
					  			
					  		}
					  		
						}
					}
				}
				
	  		}else{//account type mode
	  		var vs = $('#viewSelect a');
	      	if(vs.length) {
	  			vs[0].innerHTML = vs[0].innerHTML.replace(__["FINANCIAL INSTITUTION"],__["ACCOUNT TYPE"]).replace(__["FINANCIAL INSTITUTION"],__["ACCOUNT TYPE"]);
	  			//simply loop through maindata if by type since its already sorted by type
	  			}
	  			var html ='',firstOne=true;
	  			accountErrorModel = [];
		  		for(i=0;i<mainData.items.length;i++){
		  			var item = mainData.items[i];
		  			
		  			if(params.assetsContainers.indexOf(item.containerName)!=-1){
		  				if(firstOne){
		  					html+='<div class="sub-title white">'+__["ASSETS"]+'</div>';
		  					firstOne=false;
		  				}
		  				
		  			
			  			if(item.containerName=="BANK"){
			  				html+=subTitle+__['Banking']+'</div>';
			  			}else if(item.containerName=="STOCKS"){
			  				html+=subTitle+__['Investments']+'</div>';
			  			}else if(item.containerName=="INSURANCE"){
			  				html+=subTitle+__['Insurance']+'</div>';
			  			}else if(item.containerName=="OTHER_ASSETS"){
			  				html+=subTitle+__['Insurance']+'</div>';
			  			}else if(item.containerName=="REALESTATE"){
			  				yo.realEstateFound=true;
			  				yo.realEstateThisAccount=true;
			  				html+=subTitle+__['Real Estate']+'</div>';
			  			}else if(item.containerName=="OTHER_ASSETS"){
			  				html+=subTitle+__['Other Assets']+'</div>';
			  			}
		  				if(firstOne){
		  					html+='<div class="sub-title white">'+__["ASSETS"]+'</div>';
		  					firstOne=false;
		  				}
		  				for(j=0;j<item.accounts.length;j++){
		  					yo.getFavicon(item,j);
			  				subData.account = item.accounts[j];
			  				// Render and add to el
					      	//html += Marionette.Renderer.render(accountTemplate, subData, this);
					      var singleAccountModel = new AccountsModel(subData.account);
           	              var singleAccountView = new AccountView({model:singleAccountModel});
           	              if(subData.account.error){
           	              	accountErrorModel.push(subData.account);
           	              }
				          html += singleAccountView.render().el.innerHTML;
			  			}
			  			yo.realEstateThisAccount=false;
		  			}
		  		}//end assets for
		  		
		  		firstOne=true;
		  		for(i=0;i<mainData.items.length;i++){
		  			var item = mainData.items[i];
		  			if(params.liabilitiesContainers.indexOf(item.containerName)!=-1){
		  				if(firstOne){
		  					html+='<div class="sub-title white">'+__["LIABILITIES"]+'</div>';
		  					firstOne=false;
		  				}
		  				if(item.containerName=="CREDITS"){
			  				html+=subTitle+__['Credit Cards']+'</div>';
			  			}else if(item.containerName=="INSURANCE"){
			  				html+=subTitle+__['Insurance']+'</div>';
			  			}else if(item.containerName=="MORTGAGE"){
			  				html+=subTitle+__['Mortgages']+'</div>';
			  			}else if(item.containerName=="OTHER_LIABILITIES"){
			  				html+=subTitle+__['Other Liabilities']+'</div>';
			  			}
		  			
		  				for(j=0;j<item.accounts.length;j++){
		  					yo.getFavicon(item,j);
			  				subData.account = item.accounts[j];
			  				// Render and add to el
					      	//html += Marionette.Renderer.render(accountTemplate, subData, this);
					      var singleAccountModel = new AccountsModel(subData.account);
           	              var singleAccountView = new AccountView({model:singleAccountModel});
           	              if(subData.account.error){
           	              	accountErrorModel.push(subData.account);
           	              }
				          html += singleAccountView.render().el.innerHTML;
			  			}
		  			}
		  		}//end liabilities for
		  		
		  		firstOne=true;
		  		for(i=0;i<mainData.items.length;i++){
		  			var item = mainData.items[i];
		  			if(params.billsContainers.indexOf(item.containerName)!=-1){
		  				if(firstOne){
		  					html+='<div class="sub-title white">'+__["BILLS"]+'</div>';
		  					firstOne=false;
		  				}
			  			if(item.containerName=="BILLS"){
			  				html+=subTitle+__['Bills']+'</div>';
			  			}else if(item.containerName=="CABLE_SATELLITE"){
			  				html+=subTitle+__['Cable & Satellite']+'</div>';
			  			}else if(item.containerName=="TELEPHONE"){
			  				html+=subTitle+__['Phone & Long Distance']+'</div>';
			  			}
		  				for(j=0;j<item.accounts.length;j++){
		  					yo.getFavicon(item,j);
			  				subData.account = item.accounts[j];
			  				// Render and add to el
					      	//html += Marionette.Renderer.render(accountTemplate, subData, this);
					      var singleAccountModel = new AccountsModel(subData.account);
           	              var singleAccountView = new AccountView({model:singleAccountModel});
           	              if(subData.account.error){
           	              	accountErrorModel.push(subData.account);
           	              }
				          html += singleAccountView.render().el.innerHTML;
			  			}
		  			}
		  		}//end bills for
		  		
		  		firstOne=true;
		  		for(i=0;i<mainData.items.length;i++){
		  			var item = mainData.items[i];
		  			if(item.containerName=="REWARD_PROGRAM"||item.containerName=="MILES"){
		  				if(firstOne){
		  					html+='<div class="sub-title white">'+__["REWARDS"]+'</div>';
		  					firstOne=false;
		  				}
			  			if(item.containerName=="REWARD_PROGRAM"){
			  				html+=subTitle+__['Rewards']+'</div>';
			  			}else if(item.containerName=="MILES"){
			  				html+=subTitle+__['Miles']+'</div>';
			  			}
			  			yo.rewardsAct=true;
			  			
		  				for(j=0;j<item.accounts.length;j++){
		  					yo.getFavicon(item,j);
			  				subData.account = item.accounts[j];
			  				// Render and add to el
					      	//html += Marionette.Renderer.render(accountTemplate, subData, this);
					      var singleAccountModel = new AccountsModel(subData.account);
           	              var singleAccountView = new AccountView({model:singleAccountModel});
           	              if(subData.account.error){
           	              	accountErrorModel.push(subData.account);
           	              }
				          html += singleAccountView.render().el.innerHTML;
			  			}
			  			yo.rewardsAct=false;
		  			}
		  		}//end rewards for
		  		
		  		
	  		}
	  		
    		
			this.$el = $(this.region);
	  		//this.$el[0].innerHTML = Marionette.Renderer.render(template, this);
	  		var html1 = Marionette.Renderer.render(template, subData, this); // passing mixinTemplateHelper Obj to render
      		this.attachElContent(html1);
      		yo.getDropdownHtml('viewSelect','<li></li><li id="financialInstitution" onclick="yo.AC.loadUserSettings();" onkeyup="if(yo.enter(event)){yo.AC.loadUserSettings();}">'+__["FINANCIAL INSTITUTION"]+'</li><li id="accountType" onclick="yo.AC.loadUserSettingsByType();" onkeydown="if(event.keyCode==13||event.keyCode==32||event.keyCode==0){yo.AC.loadUserSettingsByType();}">'+__["ACCOUNT TYPE"]+'</li>',__["FINANCIAL INSTITUTION"]);
	  		if(yo.accountDisplayMode !=='fi') {
	  			var vs = $('#viewSelect a');
	      	if(vs.length) {
	  			vs[0].innerHTML = vs[0].innerHTML.replace(__["FINANCIAL INSTITUTION"],__["ACCOUNT TYPE"]).replace(__["FINANCIAL INSTITUTION"],__["ACCOUNT TYPE"]);
	  			//simply loop through maindata if by type since its already sorted by type
	  			}
	  		}
	  		$(this.el).find(".detailAccountList").html(html);
	  		$(this.el).find(".errorAccounts .accountErrorCount").html(accountErrorModel.length);
	  		var errorHTML = '';
	  		$.each(accountErrorModel,function(i,v){
            var singleAccountModel = new AccountsModel(v);
           	var singleAccountView = new AccountView({model:singleAccountModel});
	  		errorHTML += singleAccountView.render().el.innerHTML;
	  		});
	  		if(accountErrorModel.length === 0){
	  			$(this.el).find(".errorAccounts").hide();
	  		}
	  		$(this.el).find(".errorAccountsList").html(errorHTML).hide();
	  		setTimeout(function(){
	  			yo.resize();
	  		},200);
	  		
	  		return this;
    	},
    	templateHelpers : function(){
    		return {
		    	showCancelIcon:function(){
		    		return params.svg.cancelIcon;
		    	},
		    	switchEnableNotificationSettings:function(){
		    		return yo.truth(params.switchEnableNotificationSettings);
		    	},
		    	showNotificationIcon:function(){
		    		return params.svg.bell+'<i class="i-alerts"></i>';
		    	},
		    	showfilterActiveIcon:function(){
		    		return params.svg.filterActive;
		    	},
		    	showrefreshIcon:function(){
		    		return params.svg.refreshIcon+'<i class="i-refresh"></i>';
		    	},
		    	isMobile:function(){
		    		return PARAM.isMobile;
		    	},
		    	accountLabel: function() {
		    		return __["Add Account"].toUpperCase();
		    	},
		    	showAccountArrow:function() {
		    		return params.svg.downArrowError;
		    	},
           		switchEnableAccountErrors: function(){
           			return yo.truth(params.switchEnableAccountErrors);
           		},
           		ifRealEstateFound: function(){
           			return yo.realEstateFound;
           		},
           		showSmartZipLogo: function(){
           			return params.svg.smartZipLogo;
           		},
	     	    getRefreshImageUrl: function() {
	       		 if(PARAM.isMobile) {
	       		    return 'img/loader.gif';
	       	 	  } else {
	       			return '/img/loader.gif';
	       		  }
	       		}
	    	};
    	}
    });
    return AccountsView;
});



define('10003403_js/controllers/AccountsController',['10003403_js/views/AccountsView','10003403_js/models/AccountsModel','10003403_js/collections/AccountsCollection'], function(AccountsView,AccountsModel,AccountsCollection) {
	var AccountsController = Backbone.Marionette.Controller.extend({
		initialize: function() {
			console.log('Container Controller is initialized.');
  		},

		start: function(options) {
			console.log(options);
			this.region = options.region;
			var self = this;
			this.AccountsCollection = new AccountsCollection();
				if( !PARAM.accountData || !PARAM.accountData.obj.results ) {
				yo.api('/services/Account/allGrouped/', function(data){
					PARAM.accountData = data;
					self.renderAccounts(options);
				});
			}
			else {
				self.renderAccounts(options);
			}
			
		},
		
		renderAccounts :function(options){
			if( PARAM.accountData && PARAM.accountData.obj) {
    		  self.collection = new AccountsCollection(PARAM.accountData.obj.results? PARAM.accountData.obj.results: [] );
    		}
    		self.aView = new AccountsView({ collection: self.collection, moduleKey : options.moduleKey, el:options.region.el});
    		
    		self.aView.renderView();
    		 $(self.aView.region).addClass('module_10003403');
    		// var mgr = new Backbone.Marionette.Region({
			  // el: "#main-container"
			// });
    		// mgr.$el.html(self.aView.renderView().el);
			yo.uiLoad.end();
		}
	});
	return AccountsController;
});
/*yo.loadModule10003403= function() {

	if(typeof(Date)!="undefined"&&typeof(yo)!="undefined"&&typeof(yo.uiLoad)!="undefined"){*/
		
		define('10003403_js/finapp',['10003403_js/controllers/AccountsController'],function(AccountsController){
			var module = Application.Appcore.Module.extend({
			
				controller : AccountsController
			});
			return module;
		});
		
		yo.AC={
			/***loadUserSettings by type function, loads js and styles for it only on click of button
			 * 
			 */
			loadUserSettingsByType : function(){
				yo.accountDisplayMode = 'type';
				Application.Appcore.loadModule({ moduleKey : "10003204_10003403", moduleId : '10003403', el:'#body-content-js', region:false, divId:'#body-content-js'});
				$('#body-content-js')[0].style.overflowY="auto";
				$('#body-content-js')[0].style.overflowX="hidden";
				Foundation.libs.reveal.close();//all Foundation methods can be called globally hooray!
			}
			/***loadUserSettings by fi function, loads js and styles for it only on click of button
			 * 
			 */
			,loadUserSettings:function(){
				if(!PARAM.isMobile){
					yo.requireCSS(PARAM.userSettingsId);
				}
				yo.accountsRegion = '#body-content-js';
				//default display mode is by FI
		    	yo.accountDisplayMode = 'fi';
				Application.Appcore.loadModule({ moduleKey : "10003204_10003403", moduleId : '10003403', el:'#body-content-js', region:false, divId:'#body-content-js'});
				var bd = $('#body-content-js');
				bd[0].style.overflowY="auto";
				bd[0].style.overflowX="hidden";
				Foundation.libs.reveal.close();//all Foundation methods can be called globally hooray!
				bd.attr('tabindex',0);
				bd.focus();
			}
			/*hides button and then refreshes*/
			,refreshBottomButton : function(el,event){
				el.className+=' slide-down';
				yo.AC.refresh(el,event);
				setTimeout(function(){$('#main-container')[0].removeChild(el);yo.resize();},170);
			}
			
			/**refresh function to call refresh on any type of account
			 *  @param (Object) el is the element clicked on
			 * */
			,refresh : function(el,event){
				yo.endEvt(event);
				if(!el){
					var el = $('#refresh');
				}else{
					el = $(el);
				}
				
				var actId = el.attr('accountId')
				, filterString=''
				, name = el.attr('name')
				, refType = el.attr('refreshType')
				, refMode =el.attr('refreshMode')
				, siteId =el.attr('siteId')
				, siteAccId =el.attr('siteAccId');
				if(params.showRefreshButton=="true"||params.showRefreshButton==true){
					$('#refresh').addClass('loading');
				}
				
				if(typeof(actId)!="undefined"&&actId!=null){
					yo.refActId = actId;
					yo.siteRefActIds = null;
					
					if(refType=="EDIT_SITE"||refMode=="EDIT_SITE"){
						yo.AC.openEdit(actId,siteAccId,false,siteId);
						return;
					}
					if(refMode=="MFA"&&refType=="SITE_REFRESH"){
						yo.AC.openMFA(siteId, siteAccId);
						return;					
					}
					if(refMode=="MFA"&&refType=="ITEM_REFRESH"){
						yo.AC.openMFAPopup(actId, name);
						return;
					}
					if(refType=='ITEM_REFRESH'&&refMode=='NORMAL'){
						yo.refreshing=true;
						filterString  = 'filter[]=requestType,GET&filter[]=url,/v1.0/jsonsdk/Refresh/startRefresh7&jsonFilter={"itemId":"'+actId+'","refreshParameters.refreshPriority":"1","refreshParameters.refreshMode.refreshModeId":"2","refreshParameters.refreshMode.refreshMode":"NORMAL"}';
					}
					if(refType=='SITE_REFRESH'&&refMode=='NORMAL'){
						yo.refreshing=true;
						filterString  = 'filter[]=requestType,GET&filter[]=url,/v1.0/jsonsdk/Refresh/startSiteRefresh&jsonFilter={"memSiteAccId":"'+siteAccId+'","refreshParameters.refreshPriority":"1","refreshParameters.refreshMode.refreshModeId":"2","refreshParameters.refreshMode.refreshMode":"NORMAL"}';
					}
					if( 'SITE_REFRESH' == refType ) {
						yo.siteRefActIds = [];
						yo.refActId = null;
						n.all('.refresh-act-btn').each(function(el){
							if(el.data('siteaccid') == siteAccId && el.data('accountId') ) {
								yo.siteRefActIds.push(el.data('accountId'));
								el.next().removeClass('hide');
								el.addClass('hide');
								el.parent().removeClass('not-loading');//show loading on all accounts
								//el.next()._node.focus();
							}
						});
					} else {
						el.addClass('loading');
						el.find('.loader').show()//el[0].childNodes[1].focus();
					}
				}else{
					yo.refreshing=true;
					var refreshBtns = $('.refresh-btn');
					for(i=0;i<refreshBtns.length;i++){
						refreshBtns[i].className+=' loading';
					}
					
					filterString  = 'filter[]=requestType,GET&filter[]=url,/v1.0/jsonsdk/Refresh/startRefresh2&jsonFilter={"refreshPriority":"2"}';
				}
				
				if(params.refreshAtLogin!="true"){
					yo.api('/services/InternalPassThrough/makeCall/', function(data) { 
						////console.log('refresh returned:'+JSON.stringify(data));
						if(data.errorOccurred=='true'){
							var span = document.getElementById(yo.refActId+'_updatetxt');
							if(span){
								var tr = span.parentNode.parentNode.parentNode;
								//console.log('tr.getElementsByTagName(\'a\').length is:'+tr.getElementsByTagName('a').length);
								if(tr.getElementsByTagName('a').length==5){
									tr.getElementsByTagName('a')[2].className="tooltipAnchor";
									tr.getElementsByTagName('div')[2].className = "pull-left not-loading";//hide the refreshing icon
								}
							}
						}else{
							
							yo.refreshData=data;
							
							var filterStringToSend = 'filter[]=requestType,GET&filter[]=url,/v1.0/jsonsdk/Refresh/getRefreshInfo1&jsonFilter={'
							,i
							,filterStringIds=[];
							yo.pingHash={};
							
							if( yo.siteRefActIds ) {
								for(i in yo.siteRefActIds){
									filterStringIds.push(yo.siteRefActIds[i]);
									yo.pingHash[yo.siteRefActIds[i]] = false;
								}
							} else if(yo.refActId){
								
								filterStringIds.push(yo.refActId);
								yo.pingHash[yo.refActId] = false;
							}else{
								if(yo.refreshData.obj.obj){
									yo.refreshData.obj = yo.refreshData.obj.obj;
								}
								for(i in yo.refreshData.obj){
									filterStringIds.push(i);
									yo.pingHash[i] = false;
								}
							}
							for(i=0;i<filterStringIds.length;i++){
								filterStringToSend += '"itemIds['+i+']":'+filterStringIds[i];						
								if(i+1<filterStringIds.length){
									filterStringToSend+=',';
								}
							}
							filterStringToSend += '}';
							yo.AC.pingRefresh(filterStringToSend);
						}
						
						
						
					}, filterString);
				}else{
					yo.pingHash={};
					PARAM.refreshAtLogin="false";//set to false so that they can refrehs next time
					var res= PARAM.renderedData.obj.results,i,j,filterStringIds=[]
					,filterStringToSend = 'filter[]=requestType,GET&filter[]=url,/v1.0/jsonsdk/Refresh/getRefreshInfo1&jsonFilter={';
					for(i=0;i<res.length;i++){
						for(j=0;j<res[i].accounts.length;j++){
							if(res[i].accounts[j].id){
								filterStringIds.push(res[i].accounts[j].id.split('_')[0]);
								yo.pingHash[res[i].accounts[j].id.split('_')[0]] = false;
							}
						}
					}
					for(i=0;i<filterStringIds.length;i++){
						filterStringToSend += '"itemIds['+i+']":'+filterStringIds[i];						
						if(i+1<filterStringIds.length){
							filterStringToSend+=',';
						}
					}
					filterStringToSend += '}';
					yo.AC.pingRefresh(filterStringToSend);
				}
			}
			
			, pingRefresh : function(pingFilter){
							
				yo.api('/services/InternalPassThrough/makeCall/', function(data) {
					//console.log('ping received:'+JSON.stringify(data));
					if(typeof(data.obj)!="undefined"){
						for(j in data.obj){
							if(j=='indexOf'||j=='length')continue;
						
							if(typeof(data.obj[j])!="undefined"&&data.obj[j].itemAccessStatus.name=='ACCESS_VERIFIED'&&data.obj[j].lastDataUpdateAttempt.status.name=="SUCCESS"){
								//this one was successful so update the text at the right of it
								var span = document.getElementById(data.obj[j].itemId+'_updatetxt');
								if(span){
									span.innerHTML = "<i class='i-tick'></i>"+PARAM.str["Up-to-date"];
									var tr = span.parentNode.parentNode.parentNode;
									tr.getElementsByTagName('div')[2].className = "pull-left not-loading";//hide the refreshing icon
								}
							}else if(typeof(data.obj)!="undefined"&&(((data.obj[j].itemAccessStatus.name=='ACCESS_VERIFIED'||data.obj[j].itemAccessStatus.name=="ACCESS_PENDING_REVERIFICATION")&&
							(data.obj[j].lastDataUpdateAttempt.status.name=="LOGIN_FAILURE"||data.obj[j].lastDataUpdateAttempt.status.name=="DATA_SOURCE_ERROR"||
							data.obj[j].lastDataUpdateAttempt.status.name=="OTHER_ERROR"||data.obj[j].lastDataUpdateAttempt.status.name=="USER_ACTION_REQUIRED"
							||data.obj[j].lastDataUpdateAttempt.status.name=="TO_BE_CLOSED"))||data.obj[j].itemAccessStatus.name=='ACCESS_NOT_VERIFIED')){
								//this one was successful so update the text at the right of it
								var span = document.getElementById(data.obj[j].itemId+'_updatetxt');
								if(span){
									var tr = span.parentNode.parentNode.parentNode;
									if(tr.getElementsByTagName('div')[2].className.indexOf('not-loading')==-1){//not a manual account and not an account which was not loading
										
										if(data.obj[j].statusCode&&data.obj[j].statusCode!='801'){//801 is not an error state according to Meenakshi
											var atag = tr.getElementsByTagName('a')[1];
											if(atag.className.indexOf("tooltipAnchor")!=-1){
												atag.className="tooltipAnchor";
											}else{
												atag = tr.getElementsByTagName('a')[2];
												atag.className="tooltipAnchor";
											}
											
											var clonedWarning = document.getElementById('warning').cloneNode(true);
											clonedWarning.getElementsByTagName('div')[1].innerHTML = PARAM.str[data.obj[j].statusCode];
											var errorContent = clonedWarning.innerHTML.replace(/"/g,"\&quot;").replace(/'/g,"\&#39;").replace(/[>]/g,"\&gt;").replace(/[<]/g,"\&lt;");
											if(n.one('body').hasClass('ie7')||n.one('body').hasClass('ie8')){
												errorContent = errorContent.replace('&lt;DIV tabIndex=0&gt;&lt;B&gt;&lt;/B&gt;\r\n&lt;DIV&gt;','&lt;DIV tabIndex=\'0\'&gt;');
											}
											
											atag.getElementsByTagName('span')[0].innerHTML = errorContent;
											var itag = n.one(atag.getElementsByTagName('i')[0]);
											if(itag&&itag._node){
												itag.setAttribute('data-wcag-tooltip',yo.escapeJunk(errorContent));
											}
										}
										
										tr.getElementsByTagName('div')[2].className = "pull-left not-loading";//hide the refreshing icon
							
									}
								}
							}else{
								var span = document.getElementById(data.obj[j].itemId+'_updatetxt');
								if(span){
									var tr = span.parentNode.parentNode.parentNode;
									if(n.one(tr).one('.refresh-act-btn')._node){//not a manual account and not an account which was not loading
										yo.pingHash[data.obj[j].itemId]=false;
										setTimeout(function(){yo.AC.pingRefresh(pingFilter);},60000);
										return;
									}
								}
								
							}
							yo.pingHash[data.obj[j].itemId]=true;
							var allTrue=true;
							for(i in yo.pingHash){
								//console.log('i is is:'+i+' and yo.pingHash[i] is:'+yo.pingHash[i]);
									if(yo.pingHash[i]==false){
									allTrue=false;
									break;
								}
							}
							////console.log('allTrue is:'+allTrue+ 'yo.refreshing is:'+yo.refreshing);
							//if we find they are all true call the 
							if(allTrue&&yo.refreshing==true){
								yo.refreshing==false;//set semaphore to block other processes from doing the same thing	
								var drp  =n.one(".dropdown-toggle");
								yo.AC.updateTable(drp,'refresh');
								if(PARAM.showRef=="true"){
									n.one('#refresh').removeClass('loading');
									//kill 15 minute timeout
									clearTimeout(yo.AC.timeout);
								}
								if(yo.refActId){
									setTimeout(function(){
										var tr = document.getElementById(yo.refActId+'_updatetxt').parentNode.parentNode.parentNode;
										tr.getElementsByTagName('a')[1].className='refresh-act-btn show-refresh';
										tr.getElementsByTagName('a')[1].focus();
										yo.refActId=false;//wipe it out
									},500);
									
								}
							}
						}
					}
				}, pingFilter);
				
			}
		};
		
		/*var showUnvestedDisclaimer = 0, show_include_unvested_balance = 0, show_exclude_unvested_balance = 0 , hasZillowAccounts = false, TO_BE_REOPEND = 5;
		
		yo.AC = {
			data : {}
			
			
			, initMVC : function(data) {
				
				yo.uiLoad.start();
				show_include_unvested_balance = 0;
				show_exclude_unvested_balance = 0;
				
				if (!data) {
	
					// Show no data message
					n.one('body').addClass('no-data');
					n.one('.empty').removeClass('hide');
	
					// Remove loader
					yo.uiLoad.end();
					return;
				}
				
				yo.AC.accountType='1';
	
				PARAM.accountData = data;
				
				yo.AC.formatPage();
	
				
	
			}
			
			,formatPage: function(){
				
				yo.when("AccountsView", function(){
	    			var accountsView = new AccountsView();
	    			accountsView.render();
	    			// $(document).foundation();
					$(document).foundation({
					accordion: {
						active_class:'active',
						multi_expand: true,
						toggleable: true
					},
					});
				});
				
			}
			
			//stuff below here should go in the controller
			
			
			,setUpSharedHash :function(data,sharedData){
				var i,j,s
				,tableData = data.obj.results
				,shared = PARAM.sharedData;
				if(shared.obj&&shared.obj.results){
					shared = shared.obj.results;
					var sLen = shared.length;
				}
				
				for ( i=0; i<tableData.length; i++ ) {
					// Break if we dont have accounts
					if ( !data.obj.results[i].accounts ) { break; }
	
					// Store account data
					var accounts = tableData[i].accounts
					,jLen = accounts.length;
	
					// Format the account data
					for ( j=0; j<jLen; j++ ) {
						if ( accounts[j].shared ) {
							
							sharedContent = '';
							for ( s=0; s<sLen; s++ ) {
								if ( shared[s].id === accounts[j].id ) {
									// Store the sharer info for filtering
									yo.AC.data[shared[s].id] = shared[s].sharedByUserId;//crucial to do for filtering shared accounts
								}
							}
						}
					}
				}
			}
			
	
			, updateTable : function(toolbarEl, init) {
	
				if(PARAM.size=='small'){
					n.one('#mark').addClass('hide');
				}
			    else {
			        n.one('#mark').removeClass('hide');
			    }
			    
			    if(init!='refresh'){
			    	// Start spinner if not coming from refresh
					yo.uiLoad.start();
			    }
				
	
				// Get all filters
				var filter = n.one('.dropdown-toggle[data-filter]')
					, postData = []
					, thisPref
					, idValue
					, iLen
					, jLen
					, i
					, j;
					
	
				// Get & set the save pref filter	
				if (toolbarEl && toolbarEl.data('save-pref')) {
					postData.push('filter[]=save_pref,Filter.' + toolbarEl.data('save-pref'));
				}
				
				if(filter.data('filter')=='error') {
					if(!yo.AC.errorMsgHidden){
						n.one('#warning1').addClass('hide');
						n.one('#warning2').removeClass('hide');
					}
				}else{
					if(!yo.AC.errorMsgHidden){
						n.one('#warning2').addClass('hide');
						n.one('#warning1').removeClass('hide');
					}
				}
	
				// Formatting for account groups vs. system gen groups are diff
				try {
	
					// Update the save pref
					var filterData = filter.data('filter')
					, thisPref = filterData.split(',')[1] ? filterData.split(',')[1] : filterData;
	
				} catch (e){}
	
				try {
	
					// Add them filters
					idValue = filter.data('filter').split(',')[1];
					postData.push('filter[]=group_id,' + idValue);
					postData.push('filter[]=nonbilling_accounts,true');
	
				} catch (e){}
	
				
				// Save pref on update, not on load
				if (init != 'onload' && thisPref) {
	
					yo.api('/services/Preference/set/' , function(data) {
					}, 'filter[]=save_pref,' + thisPref);
	
				}
				var filterData= filter.data('filter'),
				groupIndex = filterData.indexOf('group_id');
				
				if(filterData.indexOf(',')!=-1&&filterData.split(',')[1].length>7){
					filterData = 'sharer_id,'+filterData.split(',')[1];//get rid of save_pref and replace with sharer_id since only they are this long, bug: 586208
				}
				
				
				// Filter results
				if ((groupIndex==-1&&(filterData.match(/error|financial|billpay|closed|hidden|sharer_id|sharer_all/g) ||(filterData.indexOf(',')!=-1&&filterData.split(',')[1].length==8&&!isNaN(filterData.split(',')[1]))))|| filterData.indexOf('-3')!=-1) {
	
					var makeUpdate = function(localData){
	
						var results = localData || PARAM.accountData.obj.results
							, filteredAccts = { obj: { results : {} } }
							, type = filter.data('filter')
							, keepAccounts = []
							, keepResults = []
							, resultObj = {}
							, typeArr = []
							, billpay
							, inner
							, bank
							, j;
	
						billpay = ['BILLS', 'Payment Services', 'Credit Cards', 'INSURANCE', 'UTILITIES', 'LOANS', 'Mortgages', 'TELEPHONE'];
						bank = ['Banking', 'Credit Cards', 'Investments', 'LOANS', 'Mortgages', 'OTHER_ASSETS', 'OTHER_LIABILITIES', 'Real Estate'];
	
						iLen = results.length;
						for (i =0; i<iLen; i++) {
	
							inner = results[i].accounts;
	
							// Loop thru containers, find accounts based on type
							if (type != 'financial' && type != 'billpay' && type.indexOf('closed')==-1 && type.indexOf('hidden')==-1 ) {
	
								// Shared is special based on unique UI
								if((type.indexOf(',')!=-1&&type.split(',')[1].length==8&&!isNaN(type.split(',')[1]))||type.indexOf('sharer_all')!=-1){//fix for bug:586208 -5 is the Shared Accounts group
									typeArr = type.split(',');
									type = 'shared';
								}
								
								if(type.indexOf('-3')!=-1){
									type = 'mine';
								}
	
								jLen = inner.length;
								
								for (j=0; j<jLen; j++) {
									if (typeof inner[j][type] != 'undefined' && inner[j][type].toString() !== 'false') {
										if ( type == 'shared' && (typeArr[0].indexOf('sharer_all')!=-1 || yo.AC.data[inner[j].id] === typeArr[1])) {
											keepAccounts.push( inner[j] );
										} else if (type != 'shared') {
											keepAccounts.push( inner[j] );
										}
									}
									
									if(type=='mine'&&inner[j].shared!=='true'){
										keepAccounts.push( inner[j] );
									}
								}
	
								// If we have accounts, keep the container
								if (keepAccounts.length > 0) {
	
									// Create new results obj
									resultObj = {};
									resultObj.name = results[i].name;
									resultObj.total = results[i].total;
									resultObj.containerName = results[i].containerName;
									resultObj.accounts = keepAccounts;
									keepResults.push(resultObj);
	
								}
								keepAccounts = [];
	
								// Keep all accounts in bank container
							} else if (type == 'financial' && _.contains(bank, results[i].name)) {
								keepResults.push(results[i]);
	
								// Keep all accounts in bill pay container
							} else if (type == 'billpay' && _.contains(billpay, results[i].name)) {
								keepResults.push(results[i]);
	
							} else if (type.indexOf('closed')!=-1) {
								for(j=0;j<results[i].accounts.length;j++){
									if(results[i].accounts[j].isClosed||results[i].accounts[j].isClosed=="true"){
										if(keepResults.length>0){
											if(results[i].name==keepResults[keepResults.length-1].name){
												keepResults[keepResults.length-1].accounts.push(results[i].accounts[j]);
												var conversion = PARAM.currencyData.data.results
												, one = keepResults[keepResults.length-1].total
												, two = results[i].accounts[j].amount;
												keepResults[keepResults.length-1].total[0] = ((parseFloat(one[0])*conversion[one[1]])+ (parseFloat(two[0])*conversion[two[1]])).toString();
											}else{
												keepResults.push({'accounts':[results[i].accounts[j]],'name':results[i].name,'total':[results[i].accounts[j].amount[0],results[i].accounts[j].amount[1]],'containerName':results[i].containerName});
											}
										}else{
											keepResults=[{'accounts':[results[i].accounts[j]],'name':results[i].name,'total':[results[i].accounts[j].amount[0],results[i].accounts[j].amount[1]],'containerName':results[i].containerName}];
										}
									}
								}
							} else if( type.indexOf('hidden') != -1) {
								keepResults.push(results[i]);							
							} 
	
						}
	
						// Create the right format
						filteredAccts.obj.results = keepResults;
	
						// Update the table
						if(yo.AC.justCameFromPartialCall==1){
							yo.AC.justCameFromPartialCall++;
						}
						yo.AC.postUpdate(filteredAccts,init);
						//yo.AC.renderTable(filteredAccts, PARAM.sharedData);
						PARAM.storedAccountData = filteredAccts;
						if(yo.AC.accountType==='0'&&(PARAM.size=='medium'||PARAM.size=='large')){
							n.one('#mark').removeClass('hide');
						}
					};
	
					if (filter.data('filter').match(/error/g)) {
	
						postData.push('filter[]=partial_accounts,' + true);
	
						// Request it
						yo.api('/services/Account/allGrouped/', function(data){
							if(init!='onload'){yo.AC.justCameFromPartialCall=1;}//bug: 607334 helps us prevent it from hiding the loader too early
							try {
								makeUpdate(data.obj.results);
	
							} catch (e){
	
								makeUpdate();
	
							}
	
						}, postData.join('&'));
	
					}else if (filter.data('filter').indexOf('hidden')!=-1) {
	
						postData.push('filter[]=hidden_accounts,' + true);
	
						// Request it
						yo.api('/services/Account/allGrouped/', function(data){
	
							try {
								makeUpdate(data.obj.results);
	
							} catch (e){
	
								makeUpdate();
	
							}
	
						}, postData.join('&'));
	
					} else {
	
						makeUpdate();
	
					}
	
					return;
				}//end if
				
				if(yo.AC.accountType==='1'&&(PARAM.size=='medium'||PARAM.size=='large')){
					n.one('#mark').removeClass('hide');
				}
	
				// If all accounts, do not make additional request
				if (thisPref && thisPref != 0) {
					// Request it
					yo.api('/services/Account/allGrouped/', function(data){
						yo.AC.postUpdate(data,init);
						
						PARAM.storedAccountData = data;
					}, postData.join('&'));
	
				// Render all accounts table
				} else {
					yo.AC.postUpdate(PARAM.accountData,init);
					
					PARAM.storedAccountData = PARAM.accountData;
				}
	
			}
			//function to respect preferences on View, called after update
			, postUpdate:function(data,init){
				if(PARAM.size=="small"){
					PARAM.storedAccountData = data;
					if(PARAM.prefData.data&&PARAM.prefData.data.results&&(PARAM.prefData.data.results["Filter.page_style"]=="0"||PARAM.prefData.data.results["Filter.page_style"]!="1"&&PARAM.defaultView!='type')){
						yo.AC.val = '0';
						var drp =n.one('.view');
						drp.setAttribute('data-save-pref','0');
						var atags = drp._node.getElementsByTagName('a');
						drp._node.getElementsByTagName('div')[0].title = drp._node.getElementsByTagName('div')[0].title.replace(PARAM.str.actType,PARAM.str.astLia);
						atags[0].innerHTML = atags[0].innerHTML.replace(PARAM.str.actType,PARAM.str.astLia);
						yo.AC.changeView(drp,init);
					}else{						
						yo.AC.val = '1';
						yo.AC.changeView(n.one('.dropdown-toggle').parent(),init);
					}
				}else{
					if(PARAM.prefData.data&&PARAM.prefData.data.results&&(PARAM.prefData.data.results["Filter.page_style"]=="0"||PARAM.prefData.data.results["Filter.page_style"]!="1"&&PARAM.defaultView!='type')){
						PARAM.storedAccountData = data;
						document.getElementById('radio1').click();
					}else{
						yo.AC.renderTable(data, PARAM.sharedData);
					}
				}
			}
			
			, changeView : function(el,init){
				
				
				var val='0'
					,postData=[];
				if(el._node && el._node.className.indexOf('btn-group')!=-1){
					val = el.data('save-pref');
				}else{
					val = el.value;
				}
				
				if(PARAM.size=="small"){
					n.one('#mark')._node.className='hide';
				}else {
			        n.one('#mark').removeClass('hide');
			    }
				if(val==='0'){
					if(PARAM.size!="small"){
						n.one("#mark").addClass("one").removeClass('two');
					}
					document.getElementById('body-content-js').className = 'body-content a';
				}else{
					if(PARAM.size!="small"){
						n.one("#mark").removeClass("one").addClass('two');
					}
					document.getElementById('body-content-js').className = 'body-content';
				}
			
				yo.AC.accountType = val;
				yo.AC.renderTable(PARAM.storedAccountData,PARAM.sharedData);//use the cached account data when they cahnge this setting, no need to call the back end again.
				
				if(val&&yo.AC.val!=val){//don'tr wnat it to happen on load or more than once per change
					yo.AC.val = val;
					if(init!='onload'){
						var thisPref = 'Filter.page_style='+val;
						yo.api('/services/Preference/set/' , function(data) {
							PARAM.prefData.data.results["Filter.page_style"] = val;//prefData loads on load and gets out of sync
						}, 'filter[]=save_pref,' + thisPref);
					}
				}
			}
			
	
			, renderTable : function (data, sharedData) {
				
				PARAM.renderedData=data;
				var hasAccounts = { brokerageInfo : '' , superScript: '' }
	                , mainTable = n.one('#main-table')
	                , accountFavicon = ''
					, formattedData = []
					, sharedContent = ''
					, amtColWidth = 20
					, totalLimit = 45
					, maxNameWidth=200
					, tableData = []
					, amount = PARAM.NA
					, lastUpdated
					, accountLink
					, thisAccount
					, alertClass
					, tableName
					, tempData
					, currCode
					, accounts
					, tooltip
					, account
	                , tableEl
					, shared
					, total
					, iLen
					, jLen
					, sLen
					, numActs = 0
					, i
					, j
					, s
					, kTarget
					, k
					, grandTotal
					, hdnAccountName = n.one('#hdnAccountName')
					, x
					, hasErrors=false
					, bankName= 'Placeholder Bank Name'
					, totalAssets = 0
					, totalLiabilities = 0
					, imgPath
					, heldTable=[]
					, heldAwayTable=[]
					, tempList
					, appendLater=[]
					, hasZillowAccounts = false;
				
				// Exit if we dont have data
				if ( !data.obj.results ) { return; }
				
				if(yo.AC.accountType==='0'){
	            	kTarget=1;
	            }else{
	            	kTarget=0;
	            }
	
				// Data or no data ?
				if (data.obj.results.length > 0 || kTarget) {
					n.one('body').removeClass('no-data');
					n.one('.empty').addClass('hide');
				} else {
					n.one('body').addClass('no-data');
					n.one('.empty').removeClass('hide');
				}
	
				shared = sharedData.obj.results ? sharedData.obj.results : [];
	
				// Sort the data per cobrandable order
				tempData = data.obj.results;
				iLen = tempData.length;
				
				PARAM.containerOrder= PARAM.assetsContainers+',' + PARAM.liabilitiesContainers;
				//only sort for Networth mode, otherwise just use default abc sort
				for ( i=0; i<iLen; i++ ) {
					j = _.indexOf(PARAM.containerOrder.split(','), tempData[i].name.toLowerCase());
					if ( j !== -1 ) {
						tableData[j] = tempData[i];
					}else if(kTarget==0){
						appendLater.push(tempData[i]);
					}
				}
				numActs = 51;
				// Fallback to abc sort if param is not defined
				if(kTarget==0){
					for(i=0;i<appendLater.length;i++){
						tableData.push(appendLater[i]);
					}
				}
				tableData = tableData.length > 0 ? _.compact(tableData) : tempData;
				
				
				if(PARAM.heldFirst=="true"){
					for(i=0;i<iLen;i++){
						if(tableData[i]){
							for(j=0;j<tableData[i].accounts.length;j++){
								if(tableData[i].accounts[j].isHeld==="true"){
									heldTable.push(tableData[i].accounts[j]);
								}
								else{
									heldAwayTable.push(tableData[i].accounts[j]);
								}
							}
							tableData[i].accounts= heldTable.concat(heldAwayTable);
							heldTable = [];
							heldAwayTable = [];
						}
					}
				}
				
				iLen = tableData.length;
	
	            // Empty the table
	            mainTable.setHtml('');
	            hdnAccountName.setStyle('display' ,'block');
	            
				if(PARAM.size==="small"){
					amtColWidth =15;
					totalLimit = 32;
					maxNameWidth=120;
					yo.AC.sh = true;
				}else if(PARAM.size==="olb"){
					amtColWidth=11;
					totalLimit = 15;
					maxNameWidth=120;
					yo.AC.sh = true;
				}else if(PARAM.size==="large"){
					amtColWidth=99;
					totalLimit=120;
					maxNameWidth=350;
				}
	            
	            //goes twice to assets and liabilities mode, otherwise goes once like the old finapp
	            for( k=0; k<=kTarget; k++){
			       // Format the table data
					var modeClass = ""
					, headerNode = ''
					, totalNode = ''
					, assetFooterAdded=false
					, liaFooterAdded=false
					, errorContent=''
					, grandTotal=0
					, arrowHtml=''
					, goToSiteHtml=''
					, settingsHtml=''
					, aCount = 0; // to keep track of count of accounts in asset and liabilities
					
					
					if(kTarget==1){
						if(k==0){
							modeClass = "asset";
							headerNode = '<div class="asset header"><h3 class="btm-border">'+PARAM.str.Assets+'</h3></div>';
						}else{
							modeClass = "liability";
							headerNode = '<div class="liability header"><h3 class="btm-border wtop">'+PARAM.str.Liabilities+'</h3></div>';
						}
					}
					if(headerNode!=""){
						mainTable.append(n.node.create(headerNode));
					}
					
					var titleForScrapedAccountBalance = mainTable.data('scraped-accountBalance');
						
					for ( i=0; i<iLen; i++ ) {
		
						tableName = ( tableData[i].name ).toLowerCase();
						var containerName = ( tableData[i].containerName ).toLowerCase();
						if(!kTarget||(k==0&&PARAM.assetsContainers.indexOf(tableName)!=-1)||(k==1&&PARAM.liabilitiesContainers.indexOf(tableName)!=-1)){
							
			                tableEl = n.node.create('<div class="table-container '+modeClass+'"></div>');
			
							// Break if we dont have accounts
							if ( !tableData[i].accounts ) { break; }
			
							// Store account data
							accounts = tableData[i].accounts;
							jLen = accounts.length;
			
							// Reset total to zero
							total = 0;
			
							// Format the account data
							for ( j=0; j<jLen; j++ ) {
								if(!kTarget || !accounts[j].networthTypeId || (accounts[j].networthTypeId == (k + 1) && accounts[j].isNetIncl == "true")){
									if ( accounts[j].shared ) {
										sLen = shared.length;
										sharedContent = '';
										for ( s=0; s<sLen; s++ ) {
											if ( shared[s].id === accounts[j].id ) {
												var name = '';
												if(shared[s].sharer.firstName&&shared[s].sharer.lastName){
													name = shared[s].sharer.firstName + ' '	+ shared[s].sharer.lastName + ' ';
												}else{
													name = shared[s].sharer.loginName;
												}
												sharedContent = ''
													+ '<div class="share-content">'
													+ '<i class="i-sharer"></i>'
													+ '<span class="muted">&nbsp;'
													+ name
													+ '</span></div>';
												break;
											}
										}
									} else if( accounts[j].shareeAccountInfo ) {
										var shareNames = '';
										if( accounts[j].shareeAccountInfo.ShareeDetails ) {
											if( accounts[j].shareeAccountInfo.ShareeDetails.length ) {
												sharedContent = '';
												var shareeDetails = accounts[j].shareeAccountInfo.ShareeDetails;
												var sdLen = shareeDetails.length;
												console.log(sdLen);
												for( s=0; s<sdLen; s++ ) {
													if(shareeDetails[s].firstName && shareeDetails[s].firstName){
														name = shareeDetails[s].firstName + ' '	+ shareeDetails[s].lastName;
													}else{
														name = shareeDetails[s].loginName;
													}
													if( shareNames == '' ) {
														shareNames = name;
													} else {
														shareNames += ', '+name;
													}
												}
											} else {
												var shareeDetails = accounts[j].shareeAccountInfo.ShareeDetails;
												if(shareeDetails.firstName && shareeDetails.firstName){
													shareNames = shareeDetails.firstName + ' '	+ shareeDetails.lastName;
												}else{
													shareNames = shareeDetails.loginName;
												}
											}
										}
										sharedContent = ''
											+ '<div class="share-content">'
											+ '<i class="i-sharee"></i>'
											+ '<span class="muted">&nbsp;'
											+ shareNames
											+ '</span></div>';									
									} else {
										sharedContent = '';
									}
									
									var url = ( accounts[j].homeUrl && accounts[j].homeUrl.length > 0 && accounts[j].homeUrl != accounts[j].csid && accounts[j].homeUrl != 'undefined' ) ? accounts[j].homeUrl : 'NA';
									
									var accountName = accounts[j].name;
									if(accounts[j].siteName){
										bankName = accounts[j].siteName;
										if(!accounts[j].isMan && PARAM.accountNameWithSite != "true") {
											accountName = accountName.replace(bankName+" - ", "");
										}
									} else {
										bankName = accounts[j].name;
									}
									thisAccount = yo.safeString(bankName);
									
									var accountNameSansEllipsis = yo.safeString(accounts[j].name);
									if(typeof(accounts[j].description)!='undefined'){
										accountNameSansEllipsis+= ' - '+accounts[j].description;//masked account number appended, this is shown in the top of the floater
									} 
				
									// Construct the tooltip
									
									var composite='';
									if(url!='NA'){
										composite = bankName + ' - ' + url;
									}else{
										composite= bankName;
									}
									document.getElementById('warning-lbl').innerHTML = composite;
									var clonedWarning = document.getElementById('warning').cloneNode(true)
									, firstLink = clonedWarning.getElementsByTagName('a')[0];
									
									if(accounts[j].errorCode){
										clonedWarning.getElementsByTagName('div')[1].innerHTML = PARAM.str[accounts[j].errorCode];
									}
	
									if(tableName=='real estate'){
										var subst = clonedWarning.innerHTML;
										clonedWarning.innerHTML = subst.substring(0,subst.indexOf('<a'))+subst.substring(subst.lastIndexOf('</a>')+4);
									}
									n.one(firstLink).setAttribute('onclick', 'yo.AC.openEdit(\''+accounts[j].id+'\',\''+accounts[j].siteAccountId+'\',\''+accounts[j].isMan+'\',\''+accounts[j].siteId+'\');');
									n.one(firstLink).setAttribute('onkeyup', 'if(event.keyCode==13||event.keyCode==32||event.keyCode==0){yo.AC.openEdit(\''+accounts[j].id+'\',\''+accounts[j].siteAccountId+'\',\''+accounts[j].isMan+'\',\''+accounts[j].siteId+'\');}');
									
									if(accounts[j].errorCode && accounts[j].errorCode == TO_BE_REOPEND){
										var clonedWarning = '' , firstLink = '';
	
										clonedWarning = document.getElementById('warning4').cloneNode(true);
										firstLink = clonedWarning.getElementsByTagName('a')[0];
										clonedWarning.getElementsByTagName('div')[0].innerHTML = PARAM.str[accounts[j].errorCode];
										n.one(firstLink).setAttribute('onclick', 'yo.AC.closeAcctFloater(\''+accounts[j].siteName+'\');'); //\''+accounts[j].id+'\',\''+accounts[j].siteAccountId+'\',\''+accounts[j].isMan+'\',\''+accounts[j].siteId+'\'
										n.one(firstLink).setAttribute('id', 'close-link');
										n.one(firstLink).setAttribute('onkeyup', 'if(event.keyCode==13||event.keyCode==32||event.keyCode==0){yo.AC.closeAcctFloater(\''+accounts[j].siteName+'\');}');
										n.one(firstLink).setData('item-id', accounts[j].id.split('_')[0]);
										n.one(firstLink).setData('item-account-id', accounts[j].id.split('_')[1]);
										n.one(firstLink).setData('container-val', tableData[i].name.replace(/_/g, ' '));
										n.one(firstLink).setData('is-manual', accounts[j].isMan);
	
									}else{
										if(tableName!='real estate'){
											var secondLink = clonedWarning.getElementsByTagName('a')[1];
											if(url!='NA'){
												n.one(secondLink).setData('value',url+','+accounts[j].id.split('_')[0]+','+accounts[j].isMan);
												n.one(secondLink).setData('js','AC.goToSite');
											}else{
												secondLink.parentNode.removeChild(clonedWarning.getElementsByTagName('div')[2]);	
												secondLink.parentNode.removeChild(secondLink);
											}
										}
									}
	
									errorContent = clonedWarning.innerHTML.replace(/"/g,"\&quot;").replace(/'/g,"\&#39;").replace(/[>]/g,"\&gt;").replace(/[<]/g,"\&lt;");
									if(n.one('body').hasClass('ie7')||n.one('body').hasClass('ie8')){
										errorContent = errorContent.replace('&lt;DIV tabIndex=0&gt;&lt;B&gt;&lt;/B&gt;\r\n&lt;DIV&gt;','&lt;DIV tabIndex=\'0\'&gt;');
									}
	
									tooltip = ''
											+ '<a href="#" tabindex="-1" class="tooltipAnchor '+(!accounts[j].error?"hide":"")+'">'
											+   '<span class="ada-offscreen">'
											+       errorContent
											+   '</span>'
											+   '<i data-wcag-tooltip="'
											+       errorContent
											+       '" data-position="bottom" class="i-alert" tabindex="0">'
											+   '</i>'
											+ '</a>';
									
									
									accountLink = '<span class="account-text ellips" title="'+yo.decodeString(thisAccount).replace('&lt;sup&gt;','').replace('&lt;/sup&gt;','')+'">' + yo.decodeString(thisAccount).replace("&lt;sup&gt;","<sup>").replace("&lt;/sup&gt;","</sup>") + '</span>';
									
									
									
									thisAccount = yo.decodeString(accountName);
									
									if(!accounts[j].partialSite) {
										goToSiteHtml = '<a href="#" data-value="'+url+','+accounts[j].id.split('_')[0]+','+accounts[j].isMan+'" data-js="AC.goToSite" title="'+PARAM.str.GotositeADA+'">'+PARAM.str["Go to site"]+'<span class="ada-offscreen"> - '+PARAM.str.ADAwarn+'</span></a>';
										settingsHtml = '<a href="#" title="'+PARAM.str.SettingsADA+'" onclick="yo.AC.openSettings(\''+accounts[j].id+'\',\''+accountNameSansEllipsis+'\',\''+tableData[i].name.replace(/_/g, ' ').toLowerCase()+'\',\''+url+'\',\''+bankName+'\',\''+PARAM.editFinapp+'\',\''+accounts[j].errorCode+'\');" onkeydown="if(event.keyCode==13||event.keyCode==32||event.keyCode==0){yo.AC.openSettings(\''+accounts[j].id+'\',\''+accountNameSansEllipsis+'\',\''+tableData[i].name.replace(/_/g, ' ').toLowerCase()+'\',\''+url+'\',\''+bankName+'\',\''+PARAM.editFinapp+'\',\''+accounts[j].errorCode+'\');}">'+PARAM.str["Settings"]+'<span class="ada-offscreen"> - '+PARAM.str.ADAwarn+'</span></a>';
									}
									
									if(PARAM.size=='small'){
										arrowHtml = '<a href="#" data-js="AC.showExtra" ><i class="i-arrow_down on"></i><span class="ada-hidden">'+PARAM.finappname+' - '+PARAM.str['Press Enter']+'</span></a><ul class="dropdown-menu hide extra">';
										if(accounts[j].id.split('_')[1]=='undefined'){arrowHtml+='<li><a href="#" title="'+PARAM.str.Delete+'" onclick="yo.AC.openDel(\''+accounts[j].id+'\');")>'+PARAM.str.Delete+'</a></li>';}
										if((url.indexOf('http')!=-1||url.indexOf('www')!=-1)&&tableName!='real estate'){arrowHtml +='<li>'+goToSiteHtml+'</li>';}
										arrowHtml += '<li>'+settingsHtml+'</li></ul>';
									}
									
									var isClosed=false
									,closedHtml=''
									,refreshHtml='';
									if(accounts[j].isClosed == "true" && PARAM.size!='olb') {
										if((accounts[j].id.indexOf('undefined') == -1)){
											isClosed = true;
											closedHtml = '<span class="closedTxt"> ('+PARAM.str.Closed+')</span>';
										}
									}
									if(PARAM.size!='small'){
										if(accounts[j].partialSite) {
											settingsHtml = '<a href="#" title="'+PARAM.str.Delete+'" onclick="yo.AC.openDel(\''+accounts[j].id+'\', \''+accounts[j].siteAccountId+'\');")>'+PARAM.str.Delete+'</a></li></ul>';
										} else if(accounts[j].id.split('_')[1]=='undefined'){//sample partial account:{"results":[{"name":"Banking","accounts":[{"id":"776241_undefined","
											settingsHtml = '<a href="#" title="'+PARAM.str.Delete+'" onclick="yo.AC.openDel(\''+accounts[j].id+'\');")>'+PARAM.str.Delete+'</a></li></ul>';
										}
									}
									if(!accounts[j].isMan&&PARAM.size!='small'&&PARAM.size!='olb'&&!isClosed&&accounts[j].refreshType!='NOT_REFRESHABLE'){//only have refresh button for non-manual accounts bug:574990
										var accountId = ( !accounts[j].partialSite ) ? accounts[j].id.split('_')[0] : "";
										if(diffAcctDates(accounts[j].modified, new Date())>900000){//only show refresh btn if refreshed longer than 15 mins ago
											refreshHtml='<a href="#" class="refresh-act-btn" data-accountid="'+accountId+'" data-name="'+accounts[j].name+'" data-refreshtype="'+accounts[j].refreshType+'" data-refreshmode="'+accounts[j].refreshMode+'" data-siteid="'+accounts[j].siteId+'" data-siteaccid="'+accounts[j].siteAccountId+'" onclick="yo.AC.refresh(n.one(this));" onblur="yo.AC.adaRowHide(this);" title="'+PARAM.str.Refresh+PARAM.str.RefreshADA+'"><i class="i-refresh"></i><span class="btn-text">'
												+ PARAM.str.Refresh+'<span class="ada-offscreen">'+PARAM.str.RefreshADA+' '+PARAM.finappname+'</span>'
												+ '</span></a><span class="act loading" tabindex="0"><image src="/img/loader.gif" class="loader" alt="'+PARAM.str["Refreshing"]+'"/>'+PARAM.str["Refreshing"]+'</span>';
										}
									}
				
									// Do not allow an activated link, unless an account id is present
									if ( PARAM.enableAccountLink === 'true' && !accounts[j].partialSite && accounts[j].id.indexOf('undefined') == -1) {
										accountLink = ''
										+ '<a href="#" '
										+ 'onclick="yo.AC.openSettings(\''+accounts[j].id+'\',\''+accountNameSansEllipsis+'\',\''+tableData[i].name.replace(/_/g, ' ').toLowerCase()+'\',\''+url+'\',\''+bankName+'\',\''+PARAM.transFinapp+'\',\''+accounts[j].errorCode+'\');" onkeydown="if(event.keyCode==13||event.keyCode==32||event.keyCode==0){yo.AC.openSettings(\''+accounts[j].id+'\',\''+accountNameSansEllipsis+'\',\''+tableData[i].name.replace(/_/g, ' ').toLowerCase()+'\',\''+url+'\',\''+bankName+'\',\''+PARAM.transFinapp+'\',\''+accounts[j].errorCode+'\');}" '
										+ 'class="link-account" onfocus="yo.AC.adaRowShow(this);">'
										+ accountLink + '</a>'
										+ arrowHtml+refreshHtml;
									}
									
									imgPath = accounts[j].image;
				
									if ( PARAM.showAccountFavicon === 'true' ) {
										var faviconUrl = accounts[j].image
										if(accounts[j].partialSite) {
											faviconUrl = PARAM.siteFavPrefix+'&siteId='+accounts[j].siteId;
										}
										accountFavicon = '<div class="icon"><img tabindex="0" height="15" width="15" alt="'+PARAM.str.Icon+'" title="'+PARAM.str.Icon+'" src="'+ faviconUrl +'"/></div>';
									} else {
										accountFavicon = '';
									}
				
									hasAccounts = yo.AC.stockInfo(accounts[j], mainTable, hasAccounts, containerName);
				
									// Get formatted lastUpdate
									if(accounts[j].lastUpdate){
										
										lastUpdated = accounts[j].lastUpdate;
										if(PARAM.prefs.locale!='en_US'){
											//translate it if not english
											
											var parseString = lastUpdated.split(' ')
											,m;
											lastUpdated='';
											
											for(m=0;m<parseString.length;m++){
												if(isNaN(parseString[m])&&typeof(PARAM.calLangHash[parseString[m]])!="undefined"){
													lastUpdated+=PARAM.calLangHash[parseString[m]];
												}else{
													lastUpdated+=parseString[m];
												}
												if(m+1<parseString.length)lastUpdated+=' ';
											}
										}
									}else{
										lastUpdated = yo.diffDates(accounts[j].modified, new Date(), 1);
									}
									
									//account is up to date if refreshed less than 15 mins ago
									if(diffAcctDates(accounts[j].modified, new Date())<900000){
										lastUpdated = "<i class='i-tick' alt='"+PARAM.str["Up-to-date"]+"'></i>"+lastUpdated;
									}
									
									//how is this ever going to be true
									if(PARAM.str["Up-to-date"]==lastUpdated){
										lastUpdated = "<i class='i-tick' alt='"+PARAM.str["Up-to-date"]+"'></i>"+lastUpdated;
									}
									
									
									
									if(PARAM.size!="small"){
										if(numActs<50){
											thisAccount= yo.AC.ellpisifyAccountNames(yo.safeString(thisAccount),maxNameWidth-30);
										}
									}else{
										if(numActs<50){
											thisAccount = yo.AC.ellpisifyAccountNames(yo.safeString(thisAccount),maxNameWidth) + '<br/>';
										}else{
											thisAccount = thisAccount + '<br/>';
										}
										
									}
									
									thisAccount += ( accounts[j].description ? ' - '+accounts[j].description: '' );
				
									// Account summary
									account = ''
										+ '<div class="account-block">'
										+ accountFavicon
										+ '<div class="pull-left not-loading">'
										+ accountLink + tooltip
										+ closedHtml
										+ '<div class="account-content" title="'
										if(numActs>50){
											account+='"><span class="account-lower-text ellips" title="'+thisAccount.replace('<br/>','')+'">' + thisAccount
										}else{
											account+='"><span class="account-lower-text">' + thisAccount
										}
										
										+((numActs>50)?'':thisAccount)+'"><span class="account-lower-text '+((numActs>50)?'':'ellips')+'">' + yo.safeString(thisAccount)
										account+= '</span><span class="sep">';
									
									if( accounts[j].partialSite ) {
										account += '| '+settingsHtml
										+'</span></div></div></div>'
									} else {
										
										if(url!='NA'&&(url.indexOf('http')!=-1||url.indexOf('www')!=-1)&&tableName!='real estate'){
											account+='| '+goToSiteHtml+' ';
										}
										
										account += '| '+settingsHtml
											+'</span></div>'
											+ sharedContent
											+ '</div>'
											+ hasAccounts.brokerageInfo
											+ '</div>';
									}
					
									alertClass = '';
	
									if(accounts[j].partialSite) {
										amount = PARAM.NA;
										amount += '<br/><span class="sub-text" id="'+accounts[j].siteAccountId+'_updatetxt">'+PARAM.str.Refreshed+'</span>';
										//if amount is NA make the lastUpdate be blank bug: 607611
										lastUpdated = '';
									} else if (accounts[j].amount) {
										var balanceUnit = accounts[j].amount[1];
				
										if ( parseFloat(accounts[j].amount[0]) < 0 && tableName!='credit cards') {
											alertClass = ' red-alert';
										}
				
										// Rewards are uniquely displayed
										if (tableData[i].name == 'Rewards') {
				
											// Null values should display as N/A - Bug #540106
											if ( accounts[j].amount[0] ) {
				
												if (balanceUnit && (balanceUnit == "USD" || balanceUnit == "dollars")) {
													amount = ''
													+ ( accounts[j].amount[0] ? yo.number(accounts[j].amount[0]) : 0 )
													+ ( accounts[j].amount[1] ? ' ' + accounts[j].amount[1] : '' );
												} else {
										            amount = ''
										            + ( accounts[j].amount[0] ? yo.number(Math.round(accounts[j].amount[0]), true) : 0 )
										            + ( accounts[j].amount[1] ? ' ' + accounts[j].amount[1] : '' );
												}
				
											} else {
												amount = PARAM.NA;
												//if amount is NA make the lastUpdate be blank bug: 607611
												lastUpdated = '';
											}
				
											amount = yo.wcagTooltipEllipsis(amount, amtColWidth, PARAM.ellipsifiedLabel);
											amount += '<br/><span class="sub-text" id="'+accounts[j].id.split('_')[0]+'_updatetxt">'+PARAM.str.Refreshed+' '+lastUpdated+'</span>';
										} else {
											
											if(amount==PARAM.NA&&lastUpdated==PARAM.NA){
												lastUpdated = '';
											}
				
											currCode = typeof(accounts[j].amount[1]) === 'string' ? accounts[j].amount[1] : null;
											amount = accounts[j].amount[0] && !isNaN(accounts[j].amount[0]) ? yo.wcagTooltipEllipsis(yo.money(accounts[j].amount[0], currCode, true, true, 99, true), amtColWidth, PARAM.ellipsifiedLabel) + hasAccounts.superScript : PARAM.NA;
											amount += '<br/><span class="sub-text" id="'+accounts[j].id.split('_')[0]+'_updatetxt">'+PARAM.str.Refreshed+' '+lastUpdated+'</span>';
											try {
												var amt = accounts[j].amount[0];
												if(currCode != PARAM.prefs.currencyCode){
													var exch = PARAM.currencyData.data.results[currCode];
													amt*=!isNaN(exch)? parseFloat(exch) : 0;
												}
												total += !isNaN(amt) ? parseFloat(amt) : 0;
											} catch(e) {}
				
										}
				
									}
									
									var titleText = "";
									if(containerName === 'stocks') {
										var vScrapedTotalBalanceUserd = accounts[j].scrapedTotalBalanceUsed;
										if(vScrapedTotalBalanceUserd && vScrapedTotalBalanceUserd === 'true') {
											titleText = 'title="'+titleForScrapedAccountBalance+'"';
										}
									}
									
									if(PARAM.zillowFooterNoteEnabled && PARAM.zillowFooterNoteEnabled =="true" 
										&& PARAM.realEstateCSID && accounts[j].csid){
										if(PARAM.realEstateCSID.indexOf(accounts[j].csid)!=-1){
											currCode = typeof(accounts[j].amount[1]) === 'string' ? accounts[j].amount[1] : null;
											amount = accounts[j].amount[0] && !isNaN(accounts[j].amount[0]) ? yo.wcagTooltipEllipsis(yo.money(accounts[j].amount[0], currCode, true, true, 99, true), amtColWidth, PARAM.ellipsifiedLabel) + hasAccounts.superScript : PARAM.NA;
											amount += '<span class="listDisclaimerSymbol"></span><br/><span class="sub-text" id="'+accounts[j].id.split('_')[0]+'_updatetxt">'+PARAM.str.Refreshed+' '+lastUpdated+'</span>';
											hasZillowAccounts = true;
										}	
									}
															
									formattedData.push({
				
										summary : account,
										value : '<span '+titleText+' class="amount-text'+ alertClass +'">'+ amount +'</span>'
				
									});
								}
							}
			
							// Sync received category name w/ required display name
							tableName = tableName.replace(/_/g, ' ');
							tableName = PARAM.categoryNames[tableName.replace('&amp;','&')] ? PARAM.categoryNames[tableName.replace('&amp;','&')] : tableName;
							tableName += '&nbsp;('+formattedData.length +')';
	
							alertClass = '';
							if(n.one('.dropdown-toggle[data-filter]').data('filter')!='error') {
								if( ( kTarget==0 || tableData[i].name != 'INSURANCE') && tableData[i].total ) {
									total=tableData[i].total[0];
								}
							}
							
							if(total&& tableData[i].name != 'Rewards' && formattedData.length > 0){
								grandTotal += parseFloat(total);
							}
							var totalPrelude='';
							if(kTarget==1){
								var indexOfParen = tableName.indexOf('&nbsp;(');
								totalPrelude =PARAM.str.TOTAL+' '+PARAM.str['for']+' '+tableName.substring(0,indexOfParen)+': ';
							}else{
								totalPrelude= mainTable.data('total-label');
							}
							// Rewards should not have a total
							total = tableData[i].name == 'Rewards'?'&nbsp;':totalPrelude+ yo.decodeString(yo.wcagTooltipEllipsis(yo.money(total, PARAM.prefs.currencyCode, true, true,0,true),totalLimit,PARAM.ellipsifiedLabel)); 
							if(tableData[i].name!='Rewards')formattedData.push({		
								summary : '<span class="sub-row sub-footer total">' + total.substring(0,total.indexOf('>')-1)+' class="'+alertClass+'"' +total.substring(total.indexOf('>')) + '</span>',
								value : ''
							});
			
			                // Append the table
			                // append only if there is account data, bugid 600929
			                if(tableData[i].name == 'Rewards'||formattedData.length > 1){
			                	mainTable.append(tableEl);
			                	aCount = aCount + (formattedData.length - 1)
			                }	
			                	
			            	
			                if(!assetFooterAdded&&k==0||!liaFooterAdded&&k==1){
			                	if(k==0 && aCount > 0){
									assetFooterAdded=true;
								}else if(aCount > 0){
									liaFooterAdded=true;
								}
			                }
			                
			
			                tableEl.on('render', function(el){
			
			                    // Add sub header class to tr
			                    el.target.all('.sub-footer').each(function(element){
									var tr = element.ancestor('tr');
			                        if(tr){
			                        	tr.addClass('sub-row-footer');
				                        tr.one('.col-0')._node.setAttribute('colSpan', 2);
				                        tr._node.removeChild(tr.one('.col-1')._node);
				                    }
			
			                    });
			
			                    // Add the summary
			                    el.target.one('table').setAttribute('summary',mainTable.data('table-summary'));
			
								// Set listeners to the tooltips
								mainTable.all('i[data-wcag-tooltip]').each(function(element){
			
									// Focus event doesn't bubble.  Focusin event does, but it's not supported in Firefox,
									// so we have to add listeners directly to elements for ADA support across browsers.
									element.on('focus', function(e){
										yo.wcagTooltip.doFocus = true;
										yo.wcagTooltip.show(element);
									});
				
									// Also add mousemove event
									element.on('mousemove', function(e){
										yo.wcagTooltip.doFocus = false;
										yo.wcagTooltip.show(element);
									});
				
								});
			
			                });
			                
			                var tableClass='table table-condensed table-bordered';
			                if(PARAM.size=="small"&&n.one('body').hasClass('gc')){
			                	n.one("#body-content-js").addClass('gc');
			                }
			
			                // Build the table
			                tableEl.plug('Datatable', {
			                    data: formattedData,
			                    tableClass: tableClass,
			                    rowHover : 'yo.AC.rowHover(this,event)',
			                    rowHoverOut : 'yo.AC.rowHoverOut(this)',
			                    columns: [
			                        {
			                            name : tableName,
			                            key : 'summary',
			                            disableSort : true
			                        },
			                        {
			                            name: mainTable.data('amount-label'),
			                            key : 'value',
			                            disableSort : true
			                        }
			                    ]
			                });
			                
						
			                formattedData = [];
			                
		               }
					}//end i loop
					if(assetFooterAdded&&k==0||liaFooterAdded&&k==1){//if there was data then the flags will be set to add the footer
	                	if(kTarget==1){//if we are not in type mode
							if(k==0){
								modeClass = "asset";
								totalNode = '<div class="asset footer"><div class="btm-border">'+PARAM.str['TOTAL ASSETS']+': <span class="'+((grandTotal<0)? 'red': 'green')+'">'+yo.money(grandTotal,PARAM.prefs.currencyCode, false,false,totalLimit)+'</span></div></div>';
								totalAssets = grandTotal;
							}else{
								modeClass = "liability";
								totalNode = '<div class="liability footer"><div class="btm-border">'+PARAM.str['TOTAL LIABILITIES']+': <span class="'+((grandTotal>0)? 'red': 'green')+'">'+yo.money(grandTotal,PARAM.prefs.currencyCode, false,false,totalLimit)+'</span></div></div>';
								totalLiabilities = grandTotal;
							}
							mainTable.append(n.node.create(totalNode));
						}
	                }
					if(kTarget==1){
						if(!assetFooterAdded&&k==0||!liaFooterAdded&&k==1){
							//if you never added the footer
							var str=  (k==0)?'asset':'liability';
							var bodyNode = "<div class='table-container "+str+" empty'>"+n.one('.empty')._node.innerHTML+"</div>";
							mainTable.append(n.node.create(bodyNode));
						}
					}
					
					if(kTarget==1&&k==1&&!(n.one('.table-container.liability').hasClass('empty')&&n.one('.table-container.asset').hasClass('empty'))){
						 var netWorth = totalAssets - totalLiabilities;
						 netWorthNode = '<div class="footer"><div class="btm-border nw-footer">'+PARAM.str['TOTAL NET WORTH']+': <span class="'+((netWorth<0)? 'red': 'green')+'">'+yo.money(netWorth,PARAM.prefs.currencyCode, false,false,totalLimit)+'</span></div></div>';
						 mainTable.append(n.node.create(netWorthNode));
					}
	          }//end k loop
	          
	          if(hasZillowAccounts){
	          	n.one('.zillow-disclaimer').removeClass('hide');
	          }else{
	          	n.one('.zillow-disclaimer').addClass('hide');
	          }
	           
	           // begin Suggested Accounts
	          if(!yo.AC.sh){
	          	var suggestedAccounts,a,b;
				if(PARAM.sitesData.length==0||PARAM.sitesData.indexOf('error')!=-1){
					try{
	    				if(PARAM.suggestedAccounts.length>2){suggestedAccounts = JSON.parse(PARAM.suggestedAccounts);}
	    			}catch(e){
	    				console.log('your cobranded suggested accounts had a problem: '+e);
	    			}
	          	}else{
	          		suggestedAccounts = PARAM.sitesData;
	          	}
				if (suggestedAccounts !== undefined) {
				  if (suggestedAccounts.length > 4) 
				  	console.warn('suggested accounts shall be maximum of 4');
				  if (suggestedAccounts.length === 0) 
				  	console.warn('there are no suggested accounts');
				  if (suggestedAccounts.length > 0) {
				      // create header
				      // table container (Q) Two column table kosher?
					var tableHolder = n.node.create('<div id="suggested-accounts" class="table-container row-fluid suggested"></div>'),
						tableEl = '<table class="table table-condensed table-bordered"><tbody>';
				
					var url = (window.location != window.parent.location) ? document.referrer: document.location.href;
		
					var rootFolder = PARAM.settingsStartTab.replace('/','');//could use embeddedOneLink here instead of baseUrl if we need to
				
					rootFolder = '/'+rootFolder.substring(0,rootFolder.indexOf('/'));
		
					url= url.substring(0,url.indexOf(rootFolder));
					// iterate over columns
				  	for (a = 0; a < suggestedAccounts.length; a+=2) {
				  		
				  		// create column element
				  		var rowEl = '<tr class="row-' + a + ' suggested-accounts-row">';
				  		for (b = 0; b < 2; b++) {
				  		
				  			// grab the account
				  			var account = suggestedAccounts[(a + b)];
				  			if(!account)continue;
				  			var imagePrefix = PARAM.favPrefix;
				  			
				  			
				  			if(account.contentServiceInfos){
				  				account.imageSrc = account.contentServiceInfos[0].contentServiceId;
				  			}else if(account.imageSrc.indexOf('sum_info_id=')!=-1){
				  				account.imageSrc = account.imageSrc.substring(account.imageSrc.indexOf('sum_info_id=')).replace('sum_info_id=','');
				  			}
				  			
				  			if(PARAM.sitesData.length==0){//if we are using the backup ones check to see if it exists already:
				  				var exists=false;
				  				for(i=0;i<tableData.length;i++){
				  					for(j=0;j<tableData[i].accounts.length;j++){
				  						if(tableData[i].accounts[j].csid==account.imageSrc)
				  						{
				  							exists =true;
				  							break;
				  						}
				  					}
				  					if(exists)break;
				  				}
				  				if(exists)continue;
				  			}
				  			
				  			if(imagePrefix){
				  				account.imageSrc = imagePrefix + '&sum_info_id='+ account.imageSrc;//fix for now for incorrect params since Eng refuses to check in the correct one and PS should still be able to cobrand the id numbers
				  			}
				  			
				  			var val1=(account.defaultDisplayName)?account.defaultDisplayName:account.name;
			  				rowEl += '<td class="suggested-account"><div class="icon">';
			  				if(imagePrefix){
			  					rowEl+= '<img src="' + account.imageSrc + '" width="15" height="15" alt="'+PARAM.str.Icon+'" />';
			  				}
			  				rowEl+='</div><span class="suggested-lbl" title="'+val1+'">' + val1+'</span>';
			  				if(PARAM.addAccount=='true'){
			  					var val2 = (account.contentServiceInfos)?account.contentServiceInfos[0].contentServiceId:account.id ;
			  					rowEl +=  '&nbsp;-&nbsp;<a href="#" data-js="AC.openAccountPopup" data-value="' +val2 + '" title="'+n.one('.add-account')._node.title+'">' + PARAM.str.AddAccount + '</a>';
			  				}
				  		}
						rowEl += '</td></tr>';
				  		// add the column element to the table
				  		tableEl += rowEl;
				  	}
				  	tableEl += '</tbody></table>';
					
					tableHolder.append(n.node.create('<h3 class="suggested-header">' + PARAM.str.SuggestedAccounts + ' - <a onclick=\'yo.AC.hideSuggested();\' href="#" title="'+PARAM.str.RemindMeLater+'">' + PARAM.str.RemindMeLater + '</a></h3>'));
				  	tableHolder.append(n.node.create(tableEl));
					mainTable.append(tableHolder);
				    } else {
				  	// (Q) No suggested accounts message?
				   }
				  }
		        }
				
				var res = data.obj.results;
				for(i=0;i<res.length;i++)
				{
					var acts = res[i].accounts;
					for(j=0;j<acts.length;j++){
						if(acts[j].error){
							hasErrors=true;//if the accounts have errors, flip the switch
							break;
						}
					}
				}
				
				res = PARAM.accountData.obj.results;//need to scan original data too for errors to be thorough
				for(i=0;i<res.length;i++)
				{
					var acts = res[i].accounts;
					for(j=0;j<acts.length;j++){
						if(acts[j].error){
							hasErrors=true;//if the accounts have errors, flip the switch
							break;
						}
					}
				}
		          
		        if(hasErrors&&!yo.AC.errorMsgHidden){
			  		n.one("#mark").addClass("down");
					if(n.one('.dropdown-toggle').data('filter')!='error'){
						var errDiv = n.one(".warning-container");
						errDiv.removeClass("hide");
						errDiv.one("#warning1").removeClass("hide");
						errDiv.one("#warning2").addClass("hide");
					}else{
						var errDiv = n.one(".warning-container");
						errDiv.removeClass("hide");
						errDiv.one("#warning1").addClass("hide");
						errDiv.one("#warning2").removeClass("hide");
					}
			  	}
	          
				
				hdnAccountName.setStyle('display' ,'none');
	
				// Show footnote
				if ( hasAccounts['401k'] ) {
					n.one('#footnote-js .info-401k').removeClass('hide');
				} else {
					n.one('#footnote-js .info-401k').addClass('hide');
				}
	            
				if ( hasAccounts['espp'] || hasAccounts['esopp'] ) {
					n.all('#footnote-js .info-espp').removeClass('hide');
				} else {
					n.all('#footnote-js .info-espp').addClass('hide');
				}
				
				if(show_include_unvested_balance === 1) {
					n.one('#includeBalance').removeClass('hide');
					n.one('#excludeBalance').addClass('hide');
				}
				
				if(show_exclude_unvested_balance === 1) {
					n.one('#includeBalance').addClass('hide');
					n.one('#excludeBalance').removeClass('hide');
				}
				
				if(n.one('.dropdown-toggle[data-filter]').data('filter')!='error'){
					yo.uiLoad.end();
				}else if(yo.AC.justCameFromPartialCall==2){//bug 607334
					yo.uiLoad.end();
				}else{//there is a corner case of some rare accounts where it never loads twice on error for some reason I cannot deduce so I'm setting it to stop the loading icon at a fairly safe time after the data from the second call should have loaded 
					setTimeout(function(){yo.uiLoad.end()},3000);
				}
				
				yo.resize();// following code needed only for accounts finapp due to some strange behavior in it
				
				if(!n.one('body').hasClass('ipad') && !n.one('body').hasClass('touch') && !n.one('body').hasClass('android')){//don't try this for ipad
					window.onresize.clone = function() {//make a copy of the function
					    var that = this;
					    var temp = function temporary() { return that.apply(this, arguments); };
					    for( key in this ) {
					        temp[key] = this[key];
					    }
					    return temp;
					};
					var f = window.onresize.clone();
					window.onresize = function(){yo.resize();f();};
				}
				// Remove loader
				
				function diffAcctDates(dt1, dt2){
					
					dt1 = new Date(dt1);
					var diff = dt2.getTime() - dt1.getTime();
					return diff;
				}
			}
			, ellpisifyAccountNames : function(inputString,maxWidth) {
				var hdnField = n.one('#hdnAccountName');
				var inputObject = {};
				inputObject.elementId = 'hdnAccountName';
				inputObject.text = inputString;
				inputObject.showToolTip = 'true';
				inputObject.maxWidth=maxWidth;
				//hdnField.setStyle('display', 'block');
				yo.ellipsifyLongGivenString(inputObject);
				//hdnField.setStyle('display', 'none');
				return hdnField.getHtml();
			}
			, deepLinks : function (linksParam, callback, params) {
	
				var data = [];
	
				data.push('filter[]=links,' + linksParam);
				if (params) {
					data.push('filter[]=params,' + params);
				}
	
				// Get the fancy link
				yo.api('/services/Deeplink/all/', function(data){
	
					callback.call(null, data);
	
				}, data.join('&'));
	
			}
	
			, transactionsLink : function (element) {
	
				var idsArray = element.data('accountId').split('_')
					, params
					, target = parent
					, isOLB = ''
					, url = ''
					, fnToCall = 'invokeAccountDetails';
	
				if(PARAM.locationurl){
					url = PARAM.locationurl;
				}
			
				if (n.one('#toolbar-js') && n.one('#toolbar-js').data('olb') == "true" 
					&& PARAM.olbClient && PARAM.olbClient=="true") {
					isOLB = true;
				}
				
				var isIE = yo.getInternetExplorerVersion();
				if ((isIE != -1) && (isIE < 9)) {
					if(isOLB){
						isOLB = "&isOLB=true";
					}
					
					var cacheBust = 1;
					target.location = url.replace( /#.*$/, '' ) + '#' + (+new Date) + (cacheBust++) + '&' + fnToCall + isOLB + '&' + idsArray[0] + 
						'&' + idsArray[1];
					
				} else if (isIE == 9) {
					//passing an object didn't work for IE9, data on receiver side is always a string
					target.postMessage(
						fnToCall + "," + isOLB + "," + idsArray[0] + ',' + idsArray[1]
						, encodeURI(url));
				
				} else if (target.postMessage) {
					target.postMessage(
						{
							fnToCall : fnToCall,
							isOLB : isOLB,
							detailsArray : {item_id: idsArray[0], item_account_id: idsArray[1]}
						}
						, encodeURI(url));
				}
	
			}
	
			, stockInfo : function (account, tableEl, hasAccounts, containerName) {
				hasAccounts.superScript = '';
				////console.log('account.type ---> '+JSON.stringify(account.type));
				////console.log('PARAM.showDisclaimer ---> '+PARAM.showDisclaimer);
				
				if (PARAM.showDisclaimer === '1') {
					var accountTypes = JSON.stringify(PARAM.investAcctTypes);
					////console.log('PARAM.investAcctTypes '+accountTypes+', account.type -- '+account.type);
					if (account.type !== undefined && accountTypes !== undefined && accountTypes.indexOf(account.type) !== -1) {
						
						if (account.type === 'brokerageLinkAccount') {
							hasAccounts.brokerageInfo = '<div class="sub-content">'+tableEl.data('brokerage-info')+'</div>';
						} else {
							hasAccounts.brokerageInfo = '';
						}					
						
						if (account.type === '401k') {
							hasAccounts['401k'] = true;
							hasAccounts.superScript = '<span class="superScript"><span class="ada-offscreen">'+ PARAM.adaSuperScriptText + '</span> <sup>&#'+tableEl.data('401k-marker')+';</sup></span>';
							
						} else if (account.type !== 'brokerageLinkAccount') {
							hasAccounts['esopp'] = true;
							hasAccounts.superScript = '<span class="superScript"><span class="ada-offscreen">'+ PARAM.adaSuperScriptText + '</span><sup>'+tableEl.data('esopp-marker')+'</sup></span>';
						}
					}
				} else {
						
						hasAccounts.superScript = '';
						
						if (account.type === 'esopp') {
							if (PARAM.showUnvestedBalance === '1') {
								show_include_unvested_balance = 1;
							} else {
								show_exclude_unvested_balance = 1;
							}
						}
				}
				if(containerName === 'stocks' && account.scrapedTotalBalanceUsed === "true"){
					hasAccounts['stock'] = true;
					hasAccounts.superScript = '<span class="superScript"><span class="ada-offscreen">'+ PARAM.adaSuperScriptText + '</span><sup>&#'+PARAM.scrapedInvestmentTotalBalanceSuperScript+'</sup></span>';
				}
				return hasAccounts;
	
			}
			
			
			,openDel :function(id, siteAccountId){
				//Reset the dropdown
				yo.AC.idStored = id;
				yo.AC.siteAccountIdStored = siteAccountId;
				var modal = n.one("#deleteModal");
				modal.removeClass("hide").removeClass("fade");
				n.one('.modal-backdrop').removeClass('hide');
				// WAI-ARIA: focus Mark As Paid popup title
				setTimeout(function(){
					yo.AC.oldFocus = document.activeElement;
					n.one("#delTitle")._node.focus();
				},0);
			}
			
			,closeDelete :function(e){
				if(e && e.ancestor('.modal')){
					var mode_id = e.ancestor('.modal').get('id');
					var modal = n.one('#'+mode_id);
					modal.addClass("hide").addClass("fade");
					n.one('.modal-backdrop').addClass('hide');
				}				
				if(n.one('#accountClosureConfirmationModal .modal-footer .btn-primary')){
					n.one('#accountClosureConfirmationModal .modal-footer .btn-primary').setData('action','');
				}
				yo.AC.oldFocus.focus();
			}
			
			
			,rotateDialogFocus:function(mod,e){
				try{
					n.one('#'+mod)._node.focus();
					if(e.srcElement){
						var body = document.body;
						if(body.className.indexOf('ie7')!=-1||body.className.indexOf('ie8')!=-1){
							e.returnValue = false;
							return false;
						}else{
							e.preventDefault();
						}
						
					}else{
						e.preventDefault();
					}
				}catch(error){};	
			}
			
			
			,onFocus : function(e){
				if(e.srcElement){
					if(document.body.className.indexOf('ie9')!=-1){
						if(e.srcElement.className.indexOf('dropdown-toggle')!=-1){
							e.srcElement.parentNode.className += ' dotted';
						}else{
							e.srcElement.className += ' dotted';
						}
					}
				}
			}
			
			,onBlur : function(e){
				if(e.srcElement){
					if(e.srcElement.className.indexOf('dropdown-toggle') !== -1){
						e.srcElement.parentNode.className = e.srcElement.parentNode.className.replace(' dotted','');
					}else{
						e.srcElement.className = e.srcElement.className.replace(' dotted','');
					}
				}else{
					if(e.target.className.indexOf('dropdown-toggle') !== -1){
						e.target.parentNode.className = e.target.parentNode.className.replace(' dotted','');
					}else{
						e.target.className = e.target.className.replace(' dotted','');
					}
				}
			}
			
			
			,deleteAct :function(e){
				yo.AC.closeDelete(e);
				yo.uiLoad.start();
				if(yo.AC.siteAccountIdStored){
					var filterString = 'filter[]=requestType,GET&filter[]=url,/v1.0/jsonsdk/SiteAccountManagement/removeSiteAccount&jsonFilter={"memSiteAccId":"'+yo.AC.siteAccountIdStored+'"}';
				} else if(yo.AC.idStored.indexOf('undefined')==-1){
					var filterString = 'filter[]=requestType,GET&filter[]=url,/v1.0/jsonsdk/ItemAccountManagement/removeItemAccount&jsonFilter={"itemAccountId":"'+yo.AC.idStored.split('_')[1]+'"}';
				}else{
					var filterString = 'filter[]=requestType,GET&filter[]=url,/v1.0/jsonsdk/ItemManagement/removeItem&jsonFilter={"itemId":"'+yo.AC.idStored.split('_')[0]+'"}';
				}
				
				yo.api('/services/InternalPassThrough/makeCall/', function(data) {
					yo.api('/services/Account/allGrouped/', function(data){
						PARAM.storedAccountData =data;
						PARAM.accountData = data;
						var drp  =n.one(".dropdown-toggle");
						yo.AC.updateTable(drp);
					});
				}, filterString);
			}
	
			//check the memo field values
			,memoCheck:function(sel){
				if(sel){
					if(sel.value =='others'){ 
						n.one('#closeInput').removeClass('hide');
					}else{
						n.one('#closeInput').addClass('hide');					
					}
				}
			}
			, accountAction : function (){
	
				var source = n.one('input[name=selectedMode]:checked').val();
				var el = n.one('#close-link');
				if(n.one('#accountClosureConfirmationModal .modal-footer .btn-primary').data('action')){
					source = n.one('#accountClosureConfirmationModal .modal-footer .btn-primary').data('action');
				}	
	
				if(el){
					var itemId = el.data('item-id');
					var itemAccountId = el.data('item-account-id');
					var container = el.data('container-val');
					var isManual = el.data('is-manual');
				}
	
				var lookupArray = {
					'banking':'bank',
					'investments':'stocks',
					'credit cards':'credits'
				};
				if(lookupArray[container]){
					container = lookupArray[container];
				}
	
				switch (source){
					case 'active':
						var filterString = 'filter[]=requestType,POST&filter[]=url,/v1.0/jsonsdk/ItemAccountManagement/updateItemAccountData&jsonFilter=';
						filterString += '{"accountData.itemAccountId" : '+itemAccountId+', "accountData.itemAccountStatusId" : 1}';
							yo.api('/services/InternalPassThrough/makeCall/', function(data) {
								self.location.reload();	
							}, filterString);
						 break;
					case 'reconcile':
						var reconcilePostData = {item_id: itemId, item_account_id: itemAccountId, container_val: container, is_manual : isManual}
						yo.AC.postReconcileAccAppMessage(parent, "invokeReconcileAccAppLink", reconcilePostData);
						break;
					case 'closed':
			 			n.one('#accountClosureModal').addClass('hide').addClass('fade');
			 			n.one('#accountClosureConfirmationModal').removeClass('hide').removeClass('fade');
						n.one('.modal-backdrop').removeClass('hide');
						n.one('#accountClosureConfirmationModal .modal-footer .btn-primary').setData('action','closed_confirmed');
						setTimeout(function(){
							yo.AC.oldFocus = document.activeElement;
						},0);
						break;
					case 'closed_confirmed':
						var memo = n.one('#memo').val();
						if(memo === 'others'){
							var memo_text = n.one('#others_field').val();
							if(!_.isEmpty(memo_text)){
								n.one('#error_memo').addClass('hide')
								memo = memo_text;
							}else{
								n.one('#error_memo').removeClass('hide');
								return false;
							}
						}
						var filterString1 = 'filter[]=requestType,POST&filter[]=url,/v1.0/jsonsdk/ItemAccountManagement/updateItemAccountData&jsonFilter=';
						filterString1 += '{"accountData.itemAccountId" : '+itemAccountId+', "accountData.itemAccountStatusId" : 6 , "memo" : "'+memo+'"}';
						yo.api('/services/InternalPassThrough/makeCall/', function(data) {
							self.location.reload();	
						}, filterString1);	
						break;
				}
				return false;
			}
	
			, postReconcileAccAppMessage: function(target, fnToCall, detailsArray) {			
				var isOLB = "",
					url = ""
	
				if (PARAM.locationurl) {
					url = PARAM.locationurl
				}
	
				if (n.one('#toolbar-js') && n.one('#toolbar-js').data('olb') == "true" && PARAM.olbClient && PARAM.olbClient == "true") {
					isOLB = true
				}
	
				var isIE = yo.getInternetExplorerVersion();
				if ((isIE != -1) && (isIE < 9)) {
					if (isOLB) {
						isOLB = "&isOLB=true"
					}
	
					var cacheBust = 1
					window.parent.location = url.replace(/#.*$/, '') + '#' + (+new Date) + (cacheBust++) + '&' + fnToCall + isOLB + '&itemId=' + detailsArray.item_id +
							'&itemAccountId=' + detailsArray.item_account_id + '&isManual=' + detailsArray.is_manual
				} else if (isIE == 9) {
						//passing an object didn't work for IE9, data on receiver side is always a string
						window.parent.postMessage(
							fnToCall + "," + isOLB + "," + detailsArray.item_id + ',' +
							detailsArray.item_account_id + ',' + detailsArray.containerVal + ',' + detailsArray.is_manual, encodeURI(url))
				} else if (parent.postMessage) {
						parent.postMessage({
							fnToCall: fnToCall,
							isOLB: isOLB,
							detailsArray: detailsArray
						}, encodeURI(url))
				}
			}
	
			
			, openSettings : function(id,accountName,containerName,url,bankName,selectEdit,errorCode){
				
					
				var modal = n.one('#summary');
				modal.one('#summaryTitle')._node.innerHTML = yo.safeString(accountName).replace("&lt;sup&gt;","<sup>").replace("&lt;/sup&gt;","</sup>");
				var url = (window.location != window.parent.location) ? document.referrer: document.location.href;
		
				var rootFolder = PARAM.settingsStartTab.replace('/','');//could use embeddedOneLink here instead of baseUrl if we need to
				
				rootFolder = '/'+rootFolder.substring(0,rootFolder.indexOf('/'));
		
				var URL = url.substring(0,url.indexOf(rootFolder)) + PARAM.settingsStartTab;
				var obj = yo.AC.isInError(id), composite;
				if(obj.url!='NA'){
					composite = bankName + ' - ' + obj.url;
				}else{
					composite = bankName;
				}
				document.getElementById('warning-lbl').innerHTML = composite;
							
				if(obj.isError){
					modal.one('#warning').removeClass('hide');
					modal.one('#warning')._node.getElementsByTagName('div')[1].innerHTML = PARAM.str[errorCode].split('div')[1].replace('&lt;/div&gt;','').replace('&lt;div&gt;','').replace('&lt;/','').replace('&gt;','');
					modal.one('#warning')._node.getElementsByTagName('b')[0].innerHTML = PARAM.str[errorCode].split('div')[0].replace('&lt;/b&gt;','').replace('&lt;b&gt;','').replace('&lt;','');
				}else{
					modal.one('#warning').addClass('hide');
				}
				
				var lookupArray = {
					'banking':'bank',
					'investments':'stocks',
					'credit cards':'credits'
				};
				if(lookupArray[containerName]){
					containerName = lookupArray[containerName];
				}
				var brand;
				if(location.search.indexOf('brand')!=-1){
					brand = location.search.substring(location.search.indexOf('brand')+6);
					if(brand.indexOf('&')!=-1)
					brand = brand.substring(0,brand.indexOf('&'));
				}
				
				var paramsToSend='&container='+containerName+'&itemId='+id.split('_')[0]+'&isManual=true&isShared=false&selectedTabId='+selectEdit+'&recurl='+obj.url
				+'&siteId='+obj.siteId+'&siteAccountId='+obj.siteAccountId;
				if( id.split('_')[1] && id.split('_')[1] != 'undefined' ) {
					paramsToSend+='&itemAccountId='+id.split('_')[1];
				}
				if(brand){
					paramsToSend+='&brand='+brand;
				}
				yo.AC.openSettingsPopup(modal._node.innerHTML,paramsToSend);
				
			}
			
			,isInError : function(id){
				var res= PARAM.renderedData.obj.results,i,j;
				for(i=0;i<res.length;i++){
					for(j=0;j<res[i].accounts.length;j++){
						if(res[i].accounts[j].id==id){
							return {isError:res[i].accounts[j].error,
								siteId:(res[i].accounts[j].siteId)?res[i].accounts[j].siteId:0,
								id:res[i].accounts[j].id,
								siteAccountId:(res[i].accounts[j].siteAccountId)?res[i].accounts[j].siteAccountId:0,
								url:(res[i].accounts[j].homeUrl && res[i].accounts[j].homeUrl.length > 0 && res[i].accounts[j].homeUrl != res[i].accounts[j].csid && res[i].accounts[j].homeUrl != 'undefined')?res[i].accounts[j].homeUrl:'NA'};
						}
					}
				}
			}
			
			 
			
			,refresh : function(el){
				if(!el){
					var el = n.one('#refresh');
				}
				var event = window.event;
				if(event&&event.stopPropagation){
					event.stopPropagation();
				}
				
				var actId = el.data('accountId')
				, filterString=''
				, name = el.data('name')
				, refType = el.data('refreshtype')
				, refMode =el.data('refreshmode')
				, siteId =el.data('siteid')
				, siteAccId =el.data('siteaccid');
				if(PARAM.showRef=="true"){
					n.one('#refresh').addClass('loading');
					//yo.AC.timeout = setTimeout(function(){yo.AC.openRefreshPopup()}, 900000);
				}
				
				if(typeof(actId)!="undefined"&&actId!=null){
					yo.refActId = actId;
					yo.siteRefActIds = null;
					
					if(refType=="EDIT_SITE"||refMode=="EDIT_SITE"){
						yo.AC.openEdit(actId,siteAccId,false,siteId);
						return;
					}
					if(refMode=="MFA"&&refType=="SITE_REFRESH"){
						yo.AC.openMFA(siteId, siteAccId);
						return;					
					}
					if(refMode=="MFA"&&refType=="ITEM_REFRESH"){
						yo.AC.openMFAPopup(actId, name);
						return;
					}
					if(refType=='ITEM_REFRESH'&&refMode=='NORMAL'){
						yo.refreshing=true;
						filterString  = 'filter[]=requestType,GET&filter[]=url,/v1.0/jsonsdk/Refresh/startRefresh7&jsonFilter={"itemId":"'+actId+'","refreshParameters.refreshPriority":"1","refreshParameters.refreshMode.refreshModeId":"2","refreshParameters.refreshMode.refreshMode":"NORMAL"}';
					}
					if(refType=='SITE_REFRESH'&&refMode=='NORMAL'){
						yo.refreshing=true;
						filterString  = 'filter[]=requestType,GET&filter[]=url,/v1.0/jsonsdk/Refresh/startSiteRefresh&jsonFilter={"memSiteAccId":"'+siteAccId+'","refreshParameters.refreshPriority":"1","refreshParameters.refreshMode.refreshModeId":"2","refreshParameters.refreshMode.refreshMode":"NORMAL"}';
					}
					if( 'SITE_REFRESH' == refType ) {
						yo.siteRefActIds = [];
						yo.refActId = null;
						n.all('.refresh-act-btn').each(function(el){
							if(el.data('siteaccid') == siteAccId && el.data('accountId') ) {
								yo.siteRefActIds.push(el.data('accountId'));
								el.next().removeClass('hide');
								el.addClass('hide');
								el.parent().removeClass('not-loading');//show loading on all accounts
								//el.next()._node.focus();
							}
						});
					} else {
						el.next().removeClass('hide');
						el.addClass('hide');
						el.parent().removeClass('not-loading');//show loading on all accounts
						el.next()._node.focus();
					}
				}else{
					yo.refreshing=true;
					n.all('.pull-left').each(function(el){
						
						if(el.one('.refresh-act-btn').data('refreshmode')!="MFA"){
							el.removeClass('not-loading');//show loading on all accounts
						}
					});
					
					filterString  = 'filter[]=requestType,GET&filter[]=url,/v1.0/jsonsdk/Refresh/startRefresh2&jsonFilter={"refreshPriority":"2"}';
				}
				
				if(PARAM.refreshAtLogin!="true"){
					yo.api('/services/InternalPassThrough/makeCall/', function(data) { 
						////console.log('refresh returned:'+JSON.stringify(data));
						if(data.errorOccurred=='true'){
							var span = document.getElementById(yo.refActId+'_updatetxt');
							if(span){
								var tr = span.parentNode.parentNode.parentNode;
								//console.log('tr.getElementsByTagName(\'a\').length is:'+tr.getElementsByTagName('a').length);
								if(tr.getElementsByTagName('a').length==5){
									tr.getElementsByTagName('a')[2].className="tooltipAnchor";
									tr.getElementsByTagName('div')[2].className = "pull-left not-loading";//hide the refreshing icon
								}
							}
						}else{
							
							yo.refreshData=data;
							
							var filterStringToSend = 'filter[]=requestType,GET&filter[]=url,/v1.0/jsonsdk/Refresh/getRefreshInfo1&jsonFilter={'
							,i
							,filterStringIds=[];
							yo.pingHash={};
							
							if( yo.siteRefActIds ) {
								for(i in yo.siteRefActIds){
									filterStringIds.push(yo.siteRefActIds[i]);
									yo.pingHash[yo.siteRefActIds[i]] = false;
								}
							} else if(yo.refActId){
								
								filterStringIds.push(yo.refActId);
								yo.pingHash[yo.refActId] = false;
							}else{
								if(yo.refreshData.obj.obj){
									yo.refreshData.obj = yo.refreshData.obj.obj;
								}
								for(i in yo.refreshData.obj){
									filterStringIds.push(i);
									yo.pingHash[i] = false;
								}
							}
							for(i=0;i<filterStringIds.length;i++){
								filterStringToSend += '"itemIds['+i+']":'+filterStringIds[i];						
								if(i+1<filterStringIds.length){
									filterStringToSend+=',';
								}
							}
							filterStringToSend += '}';
							yo.AC.pingRefresh(filterStringToSend);
						}
						
						
						
					}, filterString);
				}else{
					yo.pingHash={};
					PARAM.refreshAtLogin="false";//set to false so that they can refrehs next time
					var res= PARAM.renderedData.obj.results,i,j,filterStringIds=[]
					,filterStringToSend = 'filter[]=requestType,GET&filter[]=url,/v1.0/jsonsdk/Refresh/getRefreshInfo1&jsonFilter={';
					for(i=0;i<res.length;i++){
						for(j=0;j<res[i].accounts.length;j++){
							if(res[i].accounts[j].id){
								filterStringIds.push(res[i].accounts[j].id.split('_')[0]);
								yo.pingHash[res[i].accounts[j].id.split('_')[0]] = false;
							}
						}
					}
					for(i=0;i<filterStringIds.length;i++){
						filterStringToSend += '"itemIds['+i+']":'+filterStringIds[i];						
						if(i+1<filterStringIds.length){
							filterStringToSend+=',';
						}
					}
					filterStringToSend += '}';
					yo.AC.pingRefresh(filterStringToSend);
				}
			}
			
			, pingRefresh : function(pingFilter){
							
				yo.api('/services/InternalPassThrough/makeCall/', function(data) {
					//console.log('ping received:'+JSON.stringify(data));
					if(typeof(data.obj)!="undefined"){
						for(j in data.obj){
							
						
							if(typeof(data.obj[j])!="undefined"&&data.obj[j].itemAccessStatus.name=='ACCESS_VERIFIED'&&data.obj[j].lastDataUpdateAttempt.status.name=="SUCCESS"){
								//this one was successful so update the text at the right of it
								var span = document.getElementById(data.obj[j].itemId+'_updatetxt');
								if(span){
									span.innerHTML = "<i class='i-tick'></i>"+PARAM.str["Up-to-date"];
									var tr = span.parentNode.parentNode.parentNode;
									tr.getElementsByTagName('div')[2].className = "pull-left not-loading";//hide the refreshing icon
								}
							}else if(typeof(data.obj)!="undefined"&&(((data.obj[j].itemAccessStatus.name=='ACCESS_VERIFIED'||data.obj[j].itemAccessStatus.name=="ACCESS_PENDING_REVERIFICATION")&&
							(data.obj[j].lastDataUpdateAttempt.status.name=="LOGIN_FAILURE"||data.obj[j].lastDataUpdateAttempt.status.name=="DATA_SOURCE_ERROR"||
							data.obj[j].lastDataUpdateAttempt.status.name=="OTHER_ERROR"||data.obj[j].lastDataUpdateAttempt.status.name=="USER_ACTION_REQUIRED"
							||data.obj[j].lastDataUpdateAttempt.status.name=="TO_BE_CLOSED"))||data.obj[j].itemAccessStatus.name=='ACCESS_NOT_VERIFIED')){
								//this one was successful so update the text at the right of it
								var span = document.getElementById(data.obj[j].itemId+'_updatetxt');
								if(span){
									var tr = span.parentNode.parentNode.parentNode;
									if(tr.getElementsByTagName('div')[2].className.indexOf('not-loading')==-1){//not a manual account and not an account which was not loading
										
										if(data.obj[j].statusCode&&data.obj[j].statusCode!='801'){//801 is not an error state according to Meenakshi
											var atag = tr.getElementsByTagName('a')[1];
											if(atag.className.indexOf("tooltipAnchor")!=-1){
												atag.className="tooltipAnchor";
											}else{
												atag = tr.getElementsByTagName('a')[2];
												atag.className="tooltipAnchor";
											}
											
											var clonedWarning = document.getElementById('warning').cloneNode(true);
											clonedWarning.getElementsByTagName('div')[1].innerHTML = PARAM.str[data.obj[j].statusCode];
											var errorContent = clonedWarning.innerHTML.replace(/"/g,"\&quot;").replace(/'/g,"\&#39;").replace(/[>]/g,"\&gt;").replace(/[<]/g,"\&lt;");
											if(n.one('body').hasClass('ie7')||n.one('body').hasClass('ie8')){
												errorContent = errorContent.replace('&lt;DIV tabIndex=0&gt;&lt;B&gt;&lt;/B&gt;\r\n&lt;DIV&gt;','&lt;DIV tabIndex=\'0\'&gt;');
											}
											
											atag.getElementsByTagName('span')[0].innerHTML = errorContent;
											var itag = n.one(atag.getElementsByTagName('i')[0]);
											if(itag&&itag._node){
												itag.setAttribute('data-wcag-tooltip',yo.escapeJunk(errorContent));
											}
										}
										
										tr.getElementsByTagName('div')[2].className = "pull-left not-loading";//hide the refreshing icon
							
									}
								}
							}else{
								var span = document.getElementById(data.obj[j].itemId+'_updatetxt');
								if(span){
									var tr = span.parentNode.parentNode.parentNode;
									if(n.one(tr).one('.refresh-act-btn')._node){//not a manual account and not an account which was not loading
										yo.pingHash[data.obj[j].itemId]=false;
										setTimeout(function(){yo.AC.pingRefresh(pingFilter);},60000);
										return;
									}
								}
								
							}
							yo.pingHash[data.obj[j].itemId]=true;
							var allTrue=true;
							for(i in yo.pingHash){
								//console.log('i is is:'+i+' and yo.pingHash[i] is:'+yo.pingHash[i]);
									if(yo.pingHash[i]==false){
									allTrue=false;
									break;
								}
							}
							////console.log('allTrue is:'+allTrue+ 'yo.refreshing is:'+yo.refreshing);
							//if we find they are all true call the 
							if(allTrue&&yo.refreshing==true){
								yo.refreshing==false;//set semaphore to block other processes from doing the same thing	
								var drp  =n.one(".dropdown-toggle");
								yo.AC.updateTable(drp,'refresh');
								if(PARAM.showRef=="true"){
									n.one('#refresh').removeClass('loading');
									//kill 15 minute timeout
									clearTimeout(yo.AC.timeout);
								}
								if(yo.refActId){
									setTimeout(function(){
										var tr = document.getElementById(yo.refActId+'_updatetxt').parentNode.parentNode.parentNode;
										tr.getElementsByTagName('a')[1].className='refresh-act-btn show-refresh';
										tr.getElementsByTagName('a')[1].focus();
										yo.refActId=false;//wipe it out
									},500);
									
								}
							}
						}
					}
				}, pingFilter);
				
			}
			
			, openRefreshPopup : function(){
				var modal = n.one("#refreshModal");
				modal.removeClass("hide").removeClass("fade");
				n.one('.modal-backdrop').removeClass('hide');
				// WAI-ARIA: focus Mark As Paid popup title
				setTimeout(function(){
					yo.AC.oldFocus = document.activeElement;
					n.one("#refreshTitle")._node.focus();
				},0);
			}
			
			
			,closeRefreshPopup : function(){
				yo.AC.oldFocus.focus();
				var modal = n.one("#refreshModal");
				modal.addClass("hide").addClass("fade");
				n.one('.modal-backdrop').addClass('hide');
			}
			
			
			, openSettingsPopup : function(htmlPassed,prmsToSend){
				if(htmlPassed){
					yo.AC.postInvokeFloaterMessage(parent, "invokeSummaryFloater", {'htmlContent':htmlPassed,'params':prmsToSend});
				}
			}
			
			,postInvokeFloaterMessage : function (target, fnToCall, detailsArray) {
				var isOLB = ""
					, url = "";
				if(PARAM.locationurl){
					url = PARAM.locationurl;
				}
			
				if (n.one('#toolbar-js') && n.one('#toolbar-js').data('olb') == "true" && PARAM.olbClient && PARAM.olbClient=="true") {
					isOLB = true;
				}
				var isIE = yo.getInternetExplorerVersion();
				if ((isIE != -1) && (isIE < 9)) {
					if(isOLB){
						isOLB = "&isOLB=true";
					}
					
					var cacheBust = 1;
					parent.location = url.replace( /#.*$/, '' ) + '#' + (+new Date) + (cacheBust++) + '&' + fnToCall + isOLB + '&' + detailsArray.htmlContent + '&' + detailsArray.params;
				} else if (isIE == 9) {
					//passing an object didn't work for IE9, data on receiver side is always a string
					parent.postMessage(
					fnToCall + "," + isOLB + "," + detailsArray.htmlContent + ','+detailsArray.params+','+detailsArray.params//sometimes ie9 wants it to be the second param and sometimes the third so I don't care anymore send it as both!
					, encodeURI(url));
				} else if (parent.postMessage) {
					parent.postMessage(
					{
						fnToCall : fnToCall,
						isOLB : isOLB,
						detailsArray : detailsArray
					}
					, encodeURI(url));
				}
			}
			
			, openAccountPopup : function(siteId){
				if(siteId){
					siteId = siteId.data('value');
					yo.AC.postInvokeAddAccountMessage(parent, "invokeAddAccountLink", {'siteId':siteId});
				}
			}
			
			,postInvokeAddAccountMessage : function (target, fnToCall, detailsArray) {
				var isOLB = ""
					, url = "";
				
				if(PARAM.locationurl){
					url = PARAM.locationurl;
				}
			
				if (n.one('#toolbar-js') && n.one('#toolbar-js').data('olb') == "true" && PARAM.olbClient && PARAM.olbClient=="true") {
					isOLB = true;
				}
				
				var isIE = yo.getInternetExplorerVersion();
				//console.log('got here');
				if ((isIE != -1) && (isIE < 9)) {
					if(isOLB){
						isOLB = "&isOLB=true";
					}
					
					var cacheBust = 1;
					parent.location = url.replace( /#.*$/, '' ) + '#' + (+new Date) + (cacheBust++) + '&' + fnToCall + isOLB + '&' + detailsArray.siteId;
				} else if (isIE == 9) {
					//passing an object didn't work for IE9, data on receiver side is always a string
					parent.postMessage(
					fnToCall + "," + isOLB + "," + detailsArray.siteId
					, encodeURI(url));
				} else if (parent.postMessage) {
					//console.log('took last branch with:'+fnToCall+ ' isOLB: '+isOLB+ ' detailsArray is: '+JSON.stringify(detailsArray)+ ' url'+url);
					parent.postMessage(
					{
						fnToCall : fnToCall,
						isOLB : isOLB,
						detailsArray : detailsArray
					}
					, encodeURI(url));
				}
			}
			
			, goToSite : function(el){
				if(el.data('value')){
					var spl = el.data('value').split(',');
					yo.AC.postGoToSiteMessage(el, parent, "invokeGoToSite", {site:spl[0],itemId:spl[1],isManual:spl[2],goSiteOnly:PARAM.goToSiteOnlyIfSiteAutoLoginEnabled});
				}
			}
			
			, postGoToSiteMessage : function (el, target, fnToCall, detailsArray) {
				var isOLB = ""
					, url = "";
				
				if(PARAM.locationurl){
					url = PARAM.locationurl;
				}
			
				if (n.one('#toolbar-js') && n.one('#toolbar-js').data('olb') == "true" && PARAM.olbClient && PARAM.olbClient=="true") {
					isOLB = true;
				}
				
				var isIE = yo.getInternetExplorerVersion();
				if ((isIE != -1) && (isIE < 9)) {
					if(isOLB){
						isOLB = "&isOLB=true";
					}
					
					var cacheBust = 1;
					parent.location = url.replace( /#.*$/, '' ) + '#' + (+new Date) + (cacheBust++) + '&' + fnToCall + isOLB + '&' + detailsArray.site+'&'+detailsArray.itemId+'&'+detailsArray.isManual+'&'+detailsArray.goSiteOnly;
				} else if (isIE == 9) {
					//passing an object didn't work for IE9, data on receiver side is always a string
					parent.postMessage(
					fnToCall + "," + isOLB + "," + detailsArray.site+","+detailsArray.itemId+","+detailsArray.isManual+","+detailsArray.goSiteOnly
					, encodeURI(url));
				} else if (parent.postMessage) {
					parent.postMessage(
					{
						fnToCall : fnToCall,
						isOLB : isOLB,
						detailsArray : detailsArray
					}
					, encodeURI(url));
				}
			}
			
			
			, openMFAPopup : function(itemId, accountName){
				yo.AC.postMFAPopupMessage(parent, "invokeMFARefreshPopup", {item_id:itemId,account_name:accountName});
			}
			, postMFAPopupMessage : function (target, fnToCall, detailsArray) {
				var isOLB = ""
					, url = "";
				
				if(PARAM.locationurl){
					url = PARAM.locationurl;
				}
			
				if (n.one('#toolbar-js') && n.one('#toolbar-js').data('olb') == "true" && PARAM.olbClient && PARAM.olbClient=="true") {
					isOLB = true;
				}
				
				var isIE = yo.getInternetExplorerVersion();
				//console.log('got here');
				if ((isIE != -1) && (isIE < 9)) {
					if(isOLB){
						isOLB = "&isOLB=true";
					}
					
					var cacheBust = 1;
					parent.location = url.replace( /#.*$/, '' ) + '#' + (+new Date) + (cacheBust++) + '&' + fnToCall + isOLB + '&' + detailsArray.item_id+'&' + detailsArray.acount_name;
				} else if (isIE == 9) {
					//passing an object didn't work for IE9, data on receiver side is always a string
					parent.postMessage(
					fnToCall + "," + isOLB + "," + detailsArray.item_id+ "," + detailsArray.account_name
					, encodeURI(url));
				} else if (parent.postMessage) {
					//console.log('took last branch with:'+fnToCall+ ' isOLB: '+isOLB+ ' detailsArray is: '+JSON.stringify(detailsArray));
					parent.postMessage(
					{
						fnToCall : fnToCall,
						isOLB : isOLB,
						detailsArray : detailsArray
					}
					, encodeURI(url));
				}
			}
			, openMFA : function(siteIdNum, siteAccId){
				if(!siteIdNum||siteIdNum=="undefined"){
					siteIdNum=0;
				}
				if(!siteAccId||siteAccId=="undefined"){
					siteAccId=0;
				}
				yo.AC.postMFAMessage(parent, "invokeMFASiteRefreshFloater", {site_id:siteIdNum,site_account_id:siteAccId});
			}
			
			, postMFAMessage : function (target, fnToCall, detailsArray) {
				var isOLB = ""
					, url = "";
				
				if(PARAM.locationurl){
					url = PARAM.locationurl;
				}
			
				if (n.one('#toolbar-js') && n.one('#toolbar-js').data('olb') == "true" && PARAM.olbClient && PARAM.olbClient=="true") {
					isOLB = true;
				}
				
				var isIE = yo.getInternetExplorerVersion();
				//console.log('got here');
				if ((isIE != -1) && (isIE < 9)) {
					if(isOLB){
						isOLB = "&isOLB=true";
					}
					
					var cacheBust = 1;
					parent.location = url.replace( /#.*$/, '' ) + '#' + (+new Date) + (cacheBust++) + '&' + fnToCall + isOLB + '&' + detailsArray.site_id+'&' + detailsArray.site_account_id;
				} else if (isIE == 9) {
					//passing an object didn't work for IE9, data on receiver side is always a string
					parent.postMessage(
					fnToCall + "," + isOLB + "," + detailsArray.site_id+ "," + detailsArray.site_account_id
					, encodeURI(url));
				} else if (parent.postMessage) {
					//console.log('took last branch with:'+fnToCall+ ' isOLB: '+isOLB+ ' detailsArray is: '+JSON.stringify(detailsArray));
					parent.postMessage(
					{
						fnToCall : fnToCall,
						isOLB : isOLB,
						detailsArray : detailsArray
					}
					, encodeURI(url));
				}
			}
			
			, openEdit : function(itemId,siteAccId,isMan,siteIdNum){
				if(!siteIdNum||siteIdNum=="undefined"){
					siteIdNum=0;
				}
				if(!itemId||itemId=="undefined"){
					itemId=0;
				}else{
					itemId = itemId.split('_')[0];
				}
				if(!siteAccId||siteAccId=="undefined"){
					siteAccId=0;
				}
				yo.AC.postInvokeEditFloaterMessage(parent, "invokeEditSiteFloater", {site_id:siteIdNum,site_account_id:siteAccId,item_id:itemId});
				
			}
			
			,postInvokeEditFloaterMessage : function (target, fnToCall, detailsArray) {
				var isOLB = ""
					, url = "";
				if(PARAM.locationurl){
					url = PARAM.locationurl;
				}
			
				if (n.one('#toolbar-js') && n.one('#toolbar-js').data('olb') == "true" && PARAM.olbClient && PARAM.olbClient=="true") {
					isOLB = true;
				}
				var isIE = yo.getInternetExplorerVersion();
				if ((isIE != -1) && (isIE < 9)) {
					if(isOLB){
						isOLB = "&isOLB=true";
					}
					
					var cacheBust = 1;
					parent.location = url.replace( /#.*$/, '' ) + '#' + (+new Date) + (cacheBust++) + '&' + fnToCall + isOLB + '&' + detailsArray.site_id + '&' + detailsArray.site_account_id + '&' + detailsArray.item_id;
					
				} else if (isIE == 9) {
					//passing an object didn't work for IE9, data on receiver side is always a string
					parent.postMessage(
						fnToCall + "," + isOLB + ',' + detailsArray.site_id + ',' + detailsArray.site_account_id + "," + detailsArray.item_id
						, encodeURI(url));
					
				} else if (parent.postMessage) {
					parent.postMessage(
					{
						fnToCall : fnToCall,
						isOLB : isOLB,
						detailsArray : detailsArray
					}
					, encodeURI(url));
				}
			}
			
			, closeAcctFloater: function(siteName){
				n.one('#accountClosureModal').removeClass('hide').removeClass('fade');
				n.one('#accountClosureModal p').setHtml('Your account with '+siteName+' seems to be closed. Please select one of the following options')	
				n.one('.modal-backdrop').removeClass('hide');
				setTimeout(function(){
					yo.AC.oldFocus = document.activeElement;
				},0);
			}
			, showErrors : function(){
				var errDiv = n.one('.warning-container');
				errDiv.removeClass('hide');
				errDiv.one('#warning1').addClass('hide');
				errDiv.one('#warning2').removeClass('hide');
				var drp  =n.one(".dropdown-toggle");
				drp.title= PARAM.str['err']+ ' - '+ PARAM.str['press'];
				drp.one('a')._node.innerHTML= PARAM.str['err']+ '<span class="ada-hidden">'+PARAM.finappname+' - '+ PARAM.str['press']+'</span>';
				drp._node.setAttribute('data-filter','error');
				yo.AC.updateTable(drp);
				yo.resize();
			}
			
			, hideErrorMsg : function(id){
				var errDiv = n.one('.warning-container');
				errDiv.addClass('hide');
				errDiv.one('#'+id).addClass('hide');
				yo.AC.errorMsgHidden = true;//set global var to remmeber for session to not show the error message again.
				n.one("#mark").removeClass("down");
				yo.resize();
			}
			
			, hideSuggested : function(){
				n.one("#suggested-accounts")._node.style.display="none";
				yo.AC.sh = true;//suggested hidden = true
			}
			
			, returnToDefault : function(id){
				// for bugid 601330
				var errDiv = n.one('.warning-container');
				errDiv.removeClass('hide');
				errDiv.one('#warning1').removeClass('hide');
	
				var drp = n.one(".dropdown-toggle");
				drp.title = PARAM.str['all']+ ' - '+ PARAM.str['press'];
				drp.one('a')._node.innerHTML= PARAM.str['all']+ '<span class="ada-hidden">'+PARAM.finappname+' - '+ PARAM.str['press']+'</span>';
				drp._node.setAttribute('data-filter','save_pref,0');
				yo.AC.updateTable(drp);
			}
			
			
			, showExtra :function(el){
				var ul = el.parent().one('.hide');
				ul.removeClass('hide');
				ul._node.id=Math.random();
				//ul._node.getElementsByTagName('A')[0].focus();
				ul.one('A')._node.focus();
				if(yo.ul&&yo.ul._node.id!=ul._node.id){
					yo.ul.addClass('hide');
				}
				yo.ul =ul;
				if(n.one('body').hasClass('ie7')){
					ul._node.style.top = '0px';
				}
				ul._node.style.left = (16+parseInt(ul.parent().one('A')._node.offsetWidth))+'px';
				
				n.one('body').once('mouseup', function (e) {
				   if(yo.ul){
						yo.ul.addClass('hide');
					}
				});
			}
			
			, isAllowed :function(name,list){
				
				var arr = list.split(',')
				i=0;
				for(i=0;i<arr.length;i++){
					if(PARAM.str[arr[i]]==name){
						return true;
					}
				}
				return false;
			}
			
			, adaRowShow:function(el){
				if(el.nextSibling&&el.nextSibling.className==="refresh-act-btn"){
					el.nextSibling.className = "refresh-act-btn show-refresh";
				}
			}
			
			, adaRowHide:function(el){
				el.className="refresh-act-btn";
			}
			
			
			, rowHover:function(el,e){
				var body = n.one('body');
				if(yo.refreshing&&(body.hasClass('ipad')||body.hasClass('touch')||body.hasClass('android')))return;
				var target = (e.srcElement)?e.srcElement:e.target;
				if(target.tagName=='A')return;
				if(target.className.indexOf('account-text')!=-1||target.className.indexOf('noWrap')!=-1||target.parentNode.parentNode.className.indexOf('noWrap')!=-1)return;
				var atag= el.getElementsByTagName('a')[1];
				if(atag&&atag.className.indexOf('refresh-act-btn')!=-1){
					if(atag.parentNode.className.indexOf('not-loading')!=-1){
						atag.className = "refresh-act-btn show-refresh";
					}
				}
				
			}
			
			
			, rowHoverOut:function(el){
				
				var atag= el.getElementsByTagName('a')[1];
				if(atag&&atag.className.indexOf('refresh-act-btn')!=-1){
					atag.className = "refresh-act-btn";
				}
			}
		};
	
		// If we got data via graph
		if ( PARAM.accountData ) {
	
			var data = { obj : { results: PARAM.accountData.obj.results } };
			yo.AC.initMVC( data );
			return;
	
		}
	
		// Init accounts
		yo.api('/services/Account/allGrouped/', function(data){
	
			yo.AC.initMVC(data);
	
		});
	
	

	}else{
		setTimeout(yo.loadModule10003403,100);
	}
};*/;
