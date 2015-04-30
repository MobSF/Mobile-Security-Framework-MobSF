define('10003507_js/finappConfig',[],function(){ return ({
    id : "10003507",
	version : "1.0"
}) });
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

define('10003507_js/compiled/finappCompiled',['handlebars'], function(Handlebars) {
  var template = Handlebars.template, templates = Handlebars.templates = Handlebars.templates || {};
templates['tagLightBox'] = template(function (Handlebars,depth0,helpers,partials,data) {
  helpers = helpers || Handlebars.helpers;
  var buffer = "", stack1, foundHelper, self=this, functionType="function", helperMissing=helpers.helperMissing, undef=void 0, escapeExpression=this.escapeExpression;


  buffer += "\n\n		\n<label> ";
  foundHelper = helpers.action;
  stack1 = foundHelper || depth0.action;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "action", { hash: {} }); }
  buffer += escapeExpression(stack1) + "</label>\n<input onpaste=\"return false;\" type=\"text\" id=\"newTag";
  foundHelper = helpers.tId;
  stack1 = foundHelper || depth0.tId;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tId", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" class=\"newTag\"  style=\"width:auto;display:inline;margin-right:10px\" maxlength=\"40\" placeholder=\"";
  foundHelper = helpers.action;
  stack1 = foundHelper || depth0.action;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "action", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" data-dropdown=\"TagDrop";
  foundHelper = helpers.tId;
  stack1 = foundHelper || depth0.tId;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tId", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\">\n<a class=\"saveTag button\">Save</a>\n<ul id=\"TagDrop";
  foundHelper = helpers.tId;
  stack1 = foundHelper || depth0.tId;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tId", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" class=\"f-dropdown\" style=\"width:140px\" data-dropdown-content>\n	\n</ul>		\n		";
  return buffer;});
templates['transactionList'] = template(function (Handlebars,depth0,helpers,partials,data) {
  helpers = helpers || Handlebars.helpers;
  var buffer = "", stack1, stack2, foundHelper, self=this, functionType="function", helperMissing=helpers.helperMissing, undef=void 0, escapeExpression=this.escapeExpression;


  buffer += "<div class=\"timeFilter\"></div>\n<div class=\"sub-title clearfix\">\n	<div class=\"subHead\">\n		<div class=\"sideBySideColumn titleCtr\" title='";
  stack1 = "TRANSACTIONS";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "'>\n			<span tabindex=\"0\" role=\"checkbox\" class=\"checkboxCtr multiSelectCheck\" id=\"selectAllTrans\">";
  foundHelper = helpers.checkboxUnchecked;
  stack1 = foundHelper || depth0.checkboxUnchecked;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "checkboxUnchecked", { hash: {} }); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "<span class=\"ada-offscreen\">";
  stack1 = "Select all transactions";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</span></span>\n			";
  stack1 = "TRANSACTIONS";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + " \n		</div>   \n		<div class=\"sideBySideColumn inputCtr hide\">\n			<div id=\"";
  foundHelper = helpers.listMode;
  stack1 = foundHelper || depth0.listMode;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "listMode", { hash: {} }); }
  buffer += escapeExpression(stack1) + "_inputTitle\" class=\"mobileCtr inputTitle hide\">\n				<a href=\"#\" class=\"close\" title=\"";
  stack1 = "Close";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\">x</a>\n				<label for=\"";
  foundHelper = helpers.listMode;
  stack1 = foundHelper || depth0.listMode;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "listMode", { hash: {} }); }
  buffer += escapeExpression(stack1) + "_addTag\"> ";
  stack1 = "Add Tag";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</label>\n				<a href=\"#\" class=\"saveTagLink hide\" >";
  stack1 = "SAVE";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</a>\n			</div>\n			<input onpaste=\"return false;\" type=\"text\" id=\"";
  foundHelper = helpers.listMode;
  stack1 = foundHelper || depth0.listMode;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "listMode", { hash: {} }); }
  buffer += escapeExpression(stack1) + "_addTag\" class=\"addTag hide\" maxlength=\"40\" title=\"";
  stack1 = "Type tag here";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + ". ";
  stack1 = "Opens recent tags dropdown";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\" placeholder='";
  stack1 = "Type tag here";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "...' data-dropdown=\"TagDrop";
  foundHelper = helpers.tId;
  stack1 = foundHelper || depth0.tId;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tId", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\"/>\n			<ul id=\"";
  foundHelper = helpers.listMode;
  stack1 = foundHelper || depth0.listMode;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "listMode", { hash: {} }); }
  buffer += escapeExpression(stack1) + "_tagDropdown\" class=\"f-dropdown\" data-dropdown-content></ul>			\n		</div>\n		<div class=\"addTagsCtr mobileCtr hide\">\n			<a href=\"#\" role=\"button\" class=\"addTagButton button\" aria-label='";
  stack1 = "Add tags";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "'>";
  stack1 = "ADD TAG";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</a>\n		</div>\n		<div class=\"editBtnCtr \">\n			<a href=\"#\" role=\"button\" class=\"editTrans\" aria-label='";
  stack1 = "Add tag";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "'>";
  stack1 = "EDIT";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</a>\n		</div>\n	</div>\n</div>\n<div class=\"topMsgCtr hide\">\n	<p> ";
  stack1 = "Tag added successfully. To edit tag, tap on a single transaction or click the SEARCH button above";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</p>\n	<a href=\"#\" class=\"closeBtn\" title=\"Close this message\" onclick=\"document.body.removeChild(yo.msgNode);delete yo.msgNode;\"><span aria-hidden=\"true\">X</span></a>\n</div>\n<div id=\"";
  foundHelper = helpers.listMode;
  stack1 = foundHelper || depth0.listMode;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "listMode", { hash: {} }); }
  buffer += escapeExpression(stack1) + "_transactionlist\"></div>\n\n";
  return buffer;});
templates['transactionListRow'] = template(function (Handlebars,depth0,helpers,partials,data) {
  helpers = helpers || Handlebars.helpers;
  var buffer = "", stack1, stack2, foundHelper, tmp1, self=this, functionType="function", helperMissing=helpers.helperMissing, undef=void 0, escapeExpression=this.escapeExpression, blockHelperMissing=helpers.blockHelperMissing;

function program1(depth0,data) {
  
  var buffer = "", stack1;
  buffer += "\n				<div class=\"tagHeaderIcon\" id=\"tagHeaderIcon\"></div>			\n				<div id=\"tagHeader\" title=\"";
  foundHelper = helpers.tagsData;
  stack1 = foundHelper || depth0.tagsData;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tagsData", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" class=\"txnTagHeaderName\">";
  foundHelper = helpers.tagsData;
  stack1 = foundHelper || depth0.tagsData;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tagsData", { hash: {} }); }
  buffer += escapeExpression(stack1);
  foundHelper = helpers.tagCountStr;
  stack1 = foundHelper || depth0.tagCountStr;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tagCountStr", { hash: {} }); }
  buffer += escapeExpression(stack1) + "</div>\n			";
  return buffer;}

function program3(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n	<div class=\"content-row clearfix mobileSubtitleBordered\">\n		<div class=\"panel-sub-title\">";
  stack1 = "Tags";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</div>\n		<div class=\"mobileAddIcon\"><a href=\"#\" data-item-id=\"";
  foundHelper = helpers.tId;
  stack1 = foundHelper || depth0.tId;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tId", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" class=\"addTagBtnMobile\">+</a></div>\n		<div class=\"right-col tagsBox\" >\n			<div id=\"tagContainer\"></div>\n			<div class=\"black_overlay\" tabindex=\"0\">\n				<!-- Using this close anchor for edit tag overlay on desktop -->\n				<span tabindex=\"0\" href=\"#\" class=\"close-lightbox\" title=\"";
  stack1 = "Close";
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
  buffer += escapeExpression(stack1) + "\">x</span>\n			</div>\n			<div id=\"addTagModal\" class=\"TagModal addTagModal \" >\n				<!-- Using this close anchor for edit tag overlay on mobile -->\n				<a role=\"button\" tabindex=\"0\" class=\"close-lightbox\" title=\"";
  stack1 = "Close";
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
  buffer += escapeExpression(stack1) + "\">x</a>\n				<form action=\".\" onsubmit=\"return false;\">		\n					<label for=\"newTag\"> ";
  stack1 = "Add Tag";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</label>\n					<div class=\"clearfix\">\n						<div class=\"sideBySideLong\">\n							<input tabindex=\"0\" onpaste=\"return false;\" type=\"text\" id=\"newTag\" class=\"newTag\" maxlength=\"40\" title=\"";
  stack1 = "Add tag";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + ". ";
  stack1 = "Open recent tags dropdown";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\" placeholder='";
  stack1 = "Add Tag";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "' data-dropdown=\"TagDrop";
  foundHelper = helpers.tId;
  stack1 = foundHelper || depth0.tId;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tId", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" role=\"combobox\" onkeydown=\"if(event.keyCode==9){yo.endEvt(event);$(this.parentNode.parentNode).find('.saveTag')[0].focus();return;}\"/>\n							<ul id=\"TagDrop";
  foundHelper = helpers.tId;
  stack1 = foundHelper || depth0.tId;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tId", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" class=\"f-dropdown\" data-dropdown-content></ul>\n						</div>\n						<div class=\"sideBySideShortRight\">\n							<a href=\"#\" tabindex=\"0\" class=\"saveTag button disabled\" aria-label='";
  stack1 = "Add tag";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "'>";
  stack1 = "Add Tag";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</a>\n						</div>	\n					</div>\n				</form>\n				<span class=\"ada-offscreen\" onblur=\"yo.rotateDialogFocus($(this.parentNode.parentNode).find('.black_overlay')[0],event);\" onkeyDown=\"yo.rotateDialogFocus($(this.parentNode.parentNode).find('.black_overlay')[0],event);\" tabindex=\"0\" focusable=\"true\">";
  stack1 = "End of dialog content";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</span>\n			</div>\n			<a href=\"#\" id=\"addTag\" aria-label='";
  stack1 = "Add Tag";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "' class=\"addTag button primary-button\" >";
  stack1 = "Add Tag";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</a>\n			\n		</div>\n	</div>\n	";
  return buffer;}

function program5(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n	<div class=\"content-row clearfix mobileSubtitleBordered\">\n		<div class=\"panel-sub-title\">";
  stack1 = "Attachments";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</div>\n		<div class=\"mobileAddIcon\"><a href=\"#\" data-item-id=\"";
  foundHelper = helpers.tId;
  stack1 = foundHelper || depth0.tId;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tId", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" class=\"attachBtnMobile\">+</a></div>\n		<div class=\"right-col\">\n			<div class=\"attachBox clearfix\">\n				<div class=\"attachBtn\">\n					<a href=\"#\" data-item-id=\"";
  foundHelper = helpers.tId;
  stack1 = foundHelper || depth0.tId;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tId", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\">";
  foundHelper = helpers.tAttachmentAddIcon;
  stack1 = foundHelper || depth0.tAttachmentAddIcon;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tAttachmentAddIcon", { hash: {} }); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "</a>\n					<div class=\"attachHelperText\">";
  stack1 = "Accepted file types are:";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + " <span>PDF, PNG, JPEG ";
  stack1 = "and";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + " GIF.</span></div>\n				</div>\n				<form name=\"attach_item_form\" class=\"removeFromView\">\n					<input type=\"hidden\" name=\"attach_item_id\"   value=\"";
  foundHelper = helpers.tId;
  stack1 = foundHelper || depth0.tId;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tId", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" />\n					<input type=\"hidden\" name=\"attach_item_name\" value=\"";
  foundHelper = helpers.tMainDesc;
  stack1 = foundHelper || depth0.tMainDesc;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tMainDesc", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" />\n					<input type=\"file\"   name=\"attach_item_file\" accept=\"application/pdf,image/*\" />\n				</form>\n			</div>\n		</div>\n	</div>\n	";
  return buffer;}

  buffer += "\n<dl tabindex=\"0\" class=\"accordion\" data-accordion=\"\" style=\"margin-left:auto;margin-right:auto;left:0;right:0\" title=\"";
  stack1 = "Show more details for transaction with description";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + " ";
  foundHelper = helpers.tMainDesc;
  stack1 = foundHelper || depth0.tMainDesc;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tMainDesc", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\">\n<dd class=\"accordion-navigation\">\n<div tabindex=\"0\" role=\"checkbox\" class=\"checkboxCtr multiSelectCheck\" tGroup=\"";
  foundHelper = helpers.tGroup;
  stack1 = foundHelper || depth0.tGroup;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tGroup", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" tDate=\"";
  foundHelper = helpers.tTransDateGroupNumber;
  stack1 = foundHelper || depth0.tTransDateGroupNumber;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tTransDateGroupNumber", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" id=\"";
  foundHelper = helpers.tGroupId;
  stack1 = foundHelper || depth0.tGroupId;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tGroupId", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" title=\"";
  stack1 = "Select the transaction described as";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + " ";
  foundHelper = helpers.tMainDesc;
  stack1 = foundHelper || depth0.tMainDesc;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tMainDesc", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\">";
  foundHelper = helpers.checkboxUnchecked;
  stack1 = foundHelper || depth0.checkboxUnchecked;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "checkboxUnchecked", { hash: {} }); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "<span class=\"ada-offscreen\">";
  stack1 = "Select the transaction described as";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + " ";
  foundHelper = helpers.tMainDesc;
  stack1 = foundHelper || depth0.tMainDesc;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tMainDesc", { hash: {} }); }
  buffer += escapeExpression(stack1) + "</span></div>\n<a href=\"#panel";
  foundHelper = helpers.tPanelNumber;
  stack1 = foundHelper || depth0.tPanelNumber;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tPanelNumber", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" class=\"accordionAnchor\" >	\n	<div class=\"left\">\n		<div class=\"transDate\" title=\"";
  foundHelper = helpers.tDate;
  stack1 = foundHelper || depth0.tDate;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tDate", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\">";
  foundHelper = helpers.tDate;
  stack1 = foundHelper || depth0.tDate;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tDate", { hash: {} }); }
  buffer += escapeExpression(stack1) + "</div>\n	</div>\n	<div class=\"left full-mobile clear-desktop\" title=\"";
  foundHelper = helpers.tMainDesc;
  stack1 = foundHelper || depth0.tMainDesc;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tMainDesc", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\">";
  foundHelper = helpers.tMainDesc;
  stack1 = foundHelper || depth0.tMainDesc;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tMainDesc", { hash: {} }); }
  buffer += escapeExpression(stack1) + "</div>\n	<div class=\"right \">\n		<span class=\"transAmt ";
  foundHelper = helpers.tAmountClass;
  stack1 = foundHelper || depth0.tAmountClass;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tAmountClass", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" style=\"float:left\" title=\"";
  foundHelper = helpers.tFormattedAmount;
  stack1 = foundHelper || depth0.tFormattedAmount;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tFormattedAmount", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\">";
  foundHelper = helpers.tFormattedAmount;
  stack1 = foundHelper || depth0.tFormattedAmount;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tFormattedAmount", { hash: {} }); }
  buffer += escapeExpression(stack1) + "</span>\n		<span class=\"chevron\" style=\"float:none\"></span>\n	</div>\n	<div class=\"left clear-desktop\">\n		<div class=\"accordionSubTitle\">\n			";
  foundHelper = helpers.switchEnableTags;
  stack1 = foundHelper || depth0.switchEnableTags;
  tmp1 = self.program(1, program1, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  if(foundHelper && typeof stack1 === functionType) { stack1 = stack1.call(depth0, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack1, tmp1); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n		</div>\n	</div>\n</a>\n<div id=\"panel";
  foundHelper = helpers.tPanelNumber;
  stack1 = foundHelper || depth0.tPanelNumber;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tPanelNumber", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\" tabindex=\"0\" class=\"content\">\n	<div class=\"content-row clearfix\">\n		<div class=\"panel-sub-title\">";
  foundHelper = helpers.tPrefix;
  stack1 = foundHelper || depth0.tPrefix;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tPrefix", { hash: {} }); }
  buffer += escapeExpression(stack1) + "</div>\n		<div name=\"actName\" class=\"right-col\">";
  foundHelper = helpers.tAccountName;
  stack1 = foundHelper || depth0.tAccountName;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tAccountName", { hash: {} }); }
  buffer += escapeExpression(stack1) + "</div>\n	</div>\n	\n	<div class=\"content-row clearfix\">\n		<div class=\"panel-sub-title\">";
  stack1 = "Category";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</div>\n		<div class=\"right-col category\">\n			<div id=\"dropdown";
  foundHelper = helpers.tId;
  stack1 = foundHelper || depth0.tId;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tId", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\"> </div>\n		</div>\n	</div>\n\n	<div class=\"content-row clearfix mobileSubtitleBordered appearsAsRow\">\n		<div class=\"panel-sub-title\">";
  stack1 = "Appears on your statement as";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</div>\n		<div name=\"transDesc\" class=\"right-col\">";
  foundHelper = helpers.tDescription;
  stack1 = foundHelper || depth0.tDescription;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tDescription", { hash: {} }); }
  buffer += escapeExpression(stack1) + "</div>\n	</div>\n\n	";
  foundHelper = helpers.switchEnableTags;
  stack1 = foundHelper || depth0.switchEnableTags;
  tmp1 = self.program(3, program3, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  if(foundHelper && typeof stack1 === functionType) { stack1 = stack1.call(depth0, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack1, tmp1); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n	\n	";
  foundHelper = helpers.switchEnableAttachments;
  stack1 = foundHelper || depth0.switchEnableAttachments;
  tmp1 = self.program(5, program5, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  if(foundHelper && typeof stack1 === functionType) { stack1 = stack1.call(depth0, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack1, tmp1); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n\n	<div class=\"content-row clearfix\">&nbsp;</div>\n</div>\n</dd>\n</dl>";
  return buffer;});
templates['transactionSearch'] = template(function (Handlebars,depth0,helpers,partials,data) {
  helpers = helpers || Handlebars.helpers;
  var foundHelper, self=this;


  return "                              <input id=\"searchBox\" type=\"textbox\"  onpaste=\"return false;\"/>\n                  \n				<div id=\"transactionResults\"></div>\n\n\n\n";});
templates['transactionSingleTag'] = template(function (Handlebars,depth0,helpers,partials,data) {
  helpers = helpers || Handlebars.helpers;
  var buffer = "", stack1, stack2, foundHelper, self=this, functionType="function", helperMissing=helpers.helperMissing, undef=void 0, escapeExpression=this.escapeExpression;


  buffer += "<div class=\"view tagPill\" aria-label='";
  stack1 = "Edit Tag";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "' title='";
  stack1 = "Edit Tag";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + " ";
  foundHelper = helpers.tagName;
  stack1 = foundHelper || depth0.tagName;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tagName", { hash: {} }); }
  buffer += escapeExpression(stack1) + "' tabindex=\"0\" onblur=\"$(this).find('a')[0].focus();\" >\n	<div class=\"tagNamePill\" title='";
  stack1 = "Edit Tag";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + " ";
  foundHelper = helpers.tagName;
  stack1 = foundHelper || depth0.tagName;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tagName", { hash: {} }); }
  buffer += escapeExpression(stack1) + "'>";
  foundHelper = helpers.tagName;
  stack1 = foundHelper || depth0.tagName;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tagName", { hash: {} }); }
  buffer += escapeExpression(stack1) + "</div>\n	<a tabindex=\"0\" href=\"#\" aria-label='";
  stack1 = "Delete Tag";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "' title='";
  stack1 = "Delete Tag";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + " ";
  foundHelper = helpers.tagName;
  stack1 = foundHelper || depth0.tagName;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "tagName", { hash: {} }); }
  buffer += escapeExpression(stack1) + "' class=\"destroy\">\n		<i class=\"i-z0011del_btn\"></i>\n	</a>\n</div>\n\n	\n";
  return buffer;});
templates['transactionTimeFilter'] = template(function (Handlebars,depth0,helpers,partials,data) {
  helpers = helpers || Handlebars.helpers;
  var buffer = "", stack1, stack2, foundHelper, self=this, functionType="function", helperMissing=helpers.helperMissing, undef=void 0, escapeExpression=this.escapeExpression;


  buffer += "\n	<ul class=\"tabs\" data-tab=\"\">\n		<li class=\"tab-title active\"><a href=\"#tab-1 MONTH\" id=\"1m\" tabindex=\"0\" role=\"tab\">1 ";
  stack1 = "MONTH";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</a></li>\n		<li class=\"tab-title \"><a href=\"#tab-3 MONTHS\" id=\"3m\" tabindex=\"0\" role=\"tab\">3 ";
  stack1 = "MONTHS";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</a></li>\n		<li class=\"tab-title \"><a href=\"#tab-6 MONTHS\" id=\"6m\" tabindex=\"0\" role=\"tab\">6 ";
  stack1 = "MONTHS";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</a></li>\n		<li class=\"tab-title \"><a href=\"#tab-1 YEAR\" id=\"1y\" tabindex=\"0\" role=\"tab\">1 ";
  stack1 = "YEAR";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</a></li>\n		<li class=\"tab-title \"><a href=\"#tab-2 YEARS\" id=\"2y\" tabindex=\"0\" role=\"tab\">2 ";
  stack1 = "YEARS";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</a></li>\n	</ul>				\n";
  return buffer;});
return templates;
});
/**
 * Implementing model module
 * Calling yo.when to timeout till backbone loads
 * @param {Backbone} loading backbone modules
 */
define('10003507_js/models/Tag',[], function() {
	
	 Tag = Backbone.Model.extend({
        
        initialize: function(attributes, options) {
                this.tagName =  options.tagName;
				this.transactionId = options.transactionId;
				this. container =  options.container;      

        },
        
        
    });
    return Tag;
		
});
/**
 * implementing Collection module using service api
 * Putting data from api into PARAM.transData
 * @param {Backbone} loading Backbone modules
 * @param {TransactionsModel} getting Transactions model module
 */
define('10003507_js/collection/TransactionTagsCollection',['10003507_js/models/Tag'], function(Tag) {
	TransactionTagsCollection = Backbone.Collection.extend({
	
		initialize: function(){
			
			//console.log('DEBUG- Transaction Tags Collection initialization');
		},
		// define your own case insensitive where implemented using .filter
        isPresent : function( key, val ){
            return this.filter( function( item ){
                return item.get( key ).toLowerCase() === val.toLowerCase();
            });
         }, 
		
	
		model: Tag,
		
	});
	return TransactionTagsCollection;
});
		
	
/**
 * Implementing model module
 * Calling yo.when to timeout till backbone loads
 * @param {Backbone} loading backbone modules
 */
define('10003507_js/models/TransactionsModel',[], function() {
	
	TransactionsModel = Backbone.Model.extend({
		
		initialize: function(){
			//console.log('DEBUG-Initialized Transactions model');
		}
		
	});
	return TransactionsModel;	
});
/**
 * Implementing model module
 * Calling yo.when to timeout till backbone loads
 * @param {Backbone} loading backbone modules
 */
define('10003507_js/models/TransactionCache',[], function() {
    
    
    return {
     refreshTags: function(opr, tagName){
        
        
        // if(opr == 'add'){
            // this.recentTags.push(tagName);
            // this.allTags.push(tagName);
        // }
        // if(opr == 'remove'){
            // //array.indexOf doesn't work in IE8, thats why..
            // for(var i =0; this.allTags && i< this.allTags.length;i++){
                // if(tagName.toLowerCase() == this.allTags[i].toLowerCase()){
                    // this.allTags = allTags.splice(i,1);
                // }
//              
            // }
            // for(var i =0; this.recentTags && i< this.recentTags.length;i++){
                // if(tagName.toLowerCase() == this.recentTags[i].toLowerCase()){
                    // this.recentTags = recentTags.splice(i,1);
                // }    
            // }
//          
        // }
            
            
            var UserTagsModel = Backbone.Model.extend();
            //var UserTagsCollection = Backbone.Collection.extend({model: new String() });
            
            var self = this;            
            this.userTxnTagsModel = new UserTagsModel();
            
            var userTransactionTagsAPI = 'filter[]=requestType,POST&filter[]=url,/v1.0/jsonsdk/TransactionTagManagement/getUserTransactionTags&jsonFilter={"maxRecentTags":""}';
			yo.api('/services/InternalPassThrough/makeCall/', function(data) {
					PARAM.tagsData = data;
                    if (PARAM.tagsData && PARAM.tagsData.obj){
                            
                        self.recentTags = PARAM.tagsData.obj.recentTags;
                    	self.allTags = PARAM.tagsData.obj.allTags;
                    }    
                    else {
                    	console.log('Error in fetching user tags.');
                    }
			}, userTransactionTagsAPI );
            
            // this.userTxnTagsModel.fetch({reset: true,
                // url: Application.Wrapper.getAPIUrl('userTxnTags'),
//                 
                // // url : Wrapper.getAPIUrl('InternalPassThrough'),
                // //data : fileter[]=Wrapper.getAPIUrl('popularSites')&filter[]=get&filete,
                // success: function(model, response) {
                    // console.log("tags collection===",model);
                    // self.recentTags = model.attributes['recentTags'];
                    // self.allTags = model.attributes['allTags'];
                // },
                // error: function (xhr, status, errorThrown) {
                    // console.log('Error in fetching user tags.'+status);
                // }
            // }); 
     },
        
     recentTags:'',
     allTags:''
    };  
});

/**
 * Responsible for rendering individual Tag under Transaction Detail section 
 * Call to yo.when to timeout till backbone loads
 * yo.when is in base.js 
 * @param {Backbone} loading backbone modules
 * model: Tag
 * init like so: 
 * var tagView = new TransactionTagView({model: tag});
 
 */
 define('10003507_js/views/TransactionTagView',['10003507_js/compiled/finappCompiled','10003507_js/models/TransactionCache'], function(templates,TransactionCache) {
     TransactionTagView = Marionette.ItemView.extend({  
    
        template: templates['transactionSingleTag'],
        events: {
            
            "click .view"  : "edit",
            "keyup .view"  : "edit",
            "keyup .destroy" : function(e){
            	yo.endEvt(e);
            	if(yo.enter(e)){
            		this.showConfirmation(e);
            	}
            },
            "click .destroy" : "showConfirmation",
            "keypress .edit"  : "updateOnEnter",
            "blur .edit"      : "close"
        },
        initialize: function() {
        
            
            this.parentView = this.options.parentView;
            //this.listenTo(this.model, "destroy", this.remove);
        },
        onRender: function() {
                        
            this.input = this.$(".edit");
            this.$('.destroy').html(params.svg.tagDeleteIcon);
            return this;
        },
        
        edit: function() {
            //this.$el.addClass("editing");
            //this.input.focus();
            if(arguments[0].keyCode=="13"||arguments[0].type=="click"){
            	this.parentView.showEditTagDialogBox(this.model,this);
            }
        },
        close: function() {
            var value = this.input.val();
            if (!value) {
                this.clear();
            } else {
                // show loading symbol
                // make API call 
                // in success handler do
                    this.model.set({tagName: value}); //save({tagName: value});
                    this.render();
                    this.$el.removeClass("editing");
            }
        },
        updateOnEnter: function(e) {
            if(yo.enter(e)) this.close();
        },
        
        
        showConfirmation: function(e){
        	if(e){
              yo.endEvt(e);
            }
            if(e.srcElement){
            	e.target = e.srcElement;
            }
            yo.theThis = this;
            yo.clear=function(){
	            // show loading symbol
	            // make API call 
	            // in success handler do
	            $(".black_overlay_del").hide();
	            TransactionCache.refreshTags();
	            
	            yo.theThis.model.destroy();
	            yo.theThis.parentView.updateTagHeader();
	            yo.theThis.stopListening();
	            yo.theThis.remove();
	            yo.hideModalDialog();
        
            };
            
            yo.addModalDialog(yo.getModalDialogHtml({mainMsg:__["Are you sure you want to delete this tag from this transaction?"],
					btn1Class:"warning deleteTagBtn ofSameSize",
					btn1ADAMsg:__["Delete Tag"],
					btn1Msg:__["Delete"],
					btn1Func:"yo.clear();",
					btn2Class:"secondary cancelBtn ofSameSize",
					btn2ADAMsg:__["Cancel"],
					btn2Msg:__["Cancel"],
					btn2Func:"yo.hideModalDialog();"}),e.target);
        },
        
        
        /*getTemplate : function(modelJSON) {
            var content = [];
            
            content.push('<div class="view tagPill">');
            content.push('<div style="float:left">'+modelJSON.tagName+'</div>');
            content.push('<a class="destroy">X</a>');
            content.push('</div>');
            content.push('<input class="edit" type="text" value="'+modelJSON.tagName+'" />');
            return content.join('');
        }*/

    });
    
   
    return TransactionTagView;
    
});
    

/**
 * Responsible for rendering individual Tag under Transaction Detail section 
 * Call to yo.when to timeout till backbone loads
 * yo.when is in base.js 
 * @param {Backbone} loading backbone modules
 * model: Tag
 * init like so: 
 * var tagView = new TransactionRowView({model: transactionsModel});
 
 */

define('10003507_js/views/TransactionRowView',['10003507_js/compiled/finappCompiled', '10003507_js/collection/TransactionTagsCollection','10003507_js/models/TransactionsModel','10003507_js/views/TransactionTagView','10003507_js/models/TransactionCache'], function(templates, TransactionTagsCollection,TransactionsModel,TransactionTagView,TransactionCache) { 	
 	 TransactionRowView = Marionette.ItemView.extend({	
    
		template: templates['transactionListRow'],
		tagName: 'div',
		className: "transaction-row",

		events: {
			
			//"click .txnrow"  : "showTransactionDetails",
			"click .addTag" : "showAddTagDialogBox",
			"click .mobileAddIcon .addTagBtnMobile": "showAddTagDialogBox",
			"click .newTag"  : "resetRecentTagsDropdown",
			"tap   .newTag"  : "resetRecentTagsDropdown",
			"keypress .newTag"  : "createOnEnter", // changed keydown to key press
			"keyup .saveTag" : function(e){//this is the inner details one
				yo.endEvt(e);
				if(yo.enter(e)){
					this.createOnEnter(e);
				}
			},
            "click .saveTag"  : "createOnEnter",
			"click .attachBtn a": 'handleAttachAdd',
			"click .mobileAddIcon .attachBtnMobile": 'handleAttachAddMobile',
			"click .attachItem a": 'handleAttachPreview',
			"click .attachDeleteIcon": 'handleAttachRemove',
			"click .TagModal ul li": 'selectTag',
			"click .close-lightbox" : 'closeLightBox',
			"click .accordion": 'openAccordion',
			"keyup .accordion": function(e){
				if(yo.enter(e)){
					if(e.srcElement)e.target= e.srcElement;
					if(e.target.nodeName=="DL"){
						this.openAccordion(e);
					}
				}
			}
		},
		
		initialize: function() {
			//console.log('row view mode ====>',this.options.mode);
			this.transId = this.model.attributes['viewKey'].transactionId;
			this.txnId = this.options.mode+''+this.model.attributes['viewKey'].transactionId;
			this.searchView = this.options.isSearchView;			
			//this.listenTo(this.model, "change", this.render);
			this.tags = new TransactionTagsCollection();
			// may want to append txnID to newTag textbox or have only one textbox on page
			//never mind backbone is taking care of it
			this.addTagInput = this.$("#newTag");
			
			//this.listenTo(this.tags, "destroy", this.updateHeader);
			this.listenTo(this.tags, "add", this.addTag);
			
			//optimize: do it only when detail view is open
			//$(window).on("resize", this.updateCSS);

		},
		
		templateHelpers : function(){
		    var mode = this.options.mode;
		    return {
				switchEnableAttachments: function () {
					return yo.truth(params.switchEnableAttachments);
				},
				switchEnableTags: function () {
					return yo.truth(params.switchEnableTags);
				},
    		 	tPrefix: function(){
    		 		if(this.transactionBaseType=="debit"){
    		 			if(this.viewKey.containerType=="credits"){
    		 				return __["Charged to your"];
    		 			}
    		 			return __["Withdrawn from your"];
    		 		}
    		 		return __["Deposited to your"];
    		 	},
    		 	tMainDesc: function(){
    		 		if(this.description.simpleDescription){
                        var desc = this.description.simpleDescription;
                    }else{
                        var desc = this.description.description;
                    }
                    return desc;
    		 	},
    		    tAccountName: function(){
                    return this.account.accountName;
    		    },
    		    tPanelNumber: function(){
    		        return "trans"+ this.viewKey.transactionId;
    		    },
    		    tTransDateGroupNumber: function(){
    		   		var transDate = this.transactionDate;
	            	var dateStr = moment(transDate).format("MMDDYYYY");
    		    	return dateStr;
    		    },
    		    tDescription: function() {
                    return this.description.description;
                },
                tFormattedAmount: function(){
                    return yo.money(this.amount.amount,this.amount.currencyCode,false,'',true);
                },
                tAmountClass:function(){
                	if(this.amount.amount>=0){
                		return 'green';
                	}
                	return '';
                },
                tId: function(){
                	//return '';
                    return mode+''+this.viewKey.transactionId;
                },
                tagsData: function() {
                    if(typeof(this.tagNames)!="undefined"){
                        var tagData='', tagsCount = this.tagNames.length;
                        
                        if(tagsCount > 0) {
                            tagData = this.tagNames[tagsCount-1];
                        }
                    }
                    return tagData;
                },
                tagCountStr:function(){
                	if(typeof(this.tagNames)!="undefined"){
                        var tagCount='', tagsCount = this.tagNames.length;

                        if(tagsCount > 1) {
                            tagCount += '&nbsp;&&nbsp;'+ (tagsCount-1) +'&nbsp;'+ __["more"];
                        }                           
                    }
                    return tagCount; 
                },
                tAccId : function() {
                  return this.account.itemAccountId;  
                },
                downArrowSVG: function() {
                    //$('.chevron')[0].innerHTML = ((yo.IE==8)?'<i class="i-z0019up_arrow"></i>':params.svg.upArrow);
                    //return ((yo.IE==8)?  '<i class=\"i-z0012down_arrow\"></i>': params.svg.downArrow);
                    return '';
                },
                recentUserTags: function(){
                    return TransactionCache.recentTags;
                },
				tAttachmentAddIcon: function() {
					return (yo.IE==8) ? '<i>[Add]</i>' : params.svg.attachAddIcon;
				},
                tDate: function() {
                 
	            	var transDate = this.transactionDate;
	            	var dateStr = moment(transDate).format("MMMM DD, YYYY");
	            	if(this.searchView){
	            		var today = moment(new Date()).format("MMMM/DD/YYYY");
						var txnDate = moment(transDate).format("MMMM/DD/YYYY");
						var yesterday = moment(new Date()).subtract(1, 'days').format("MMMM/DD/YYYY");
						var tomorrow = moment(new Date()).add(1, 'days').format("MMMM/DD/YYYY");
						
						if(today == txnDate) dateStr = "Today";
						if(tomorrow == txnDate) dateStr = "Tomorrow";
						if(yesterday == txnDate) dateStr = "Yesterday";
					}
					return dateStr;
				},
				tCategory:function(){
					return __[this.category.categoryName];
				},
				tAttributes:function(){
					var attributes={//data-attributes needed in the dropdown html for changing Category
						"categoryId":this.category.categoryId,
						"categoryLevelId":this.category.categoryLevelId,
						"containerType":this.viewKey.containerType,
						"transactionId":this.viewKey.transactionId
					};
					return JSON.stringify(attributes);
				},
				checkboxUnchecked: function(){
					return (yo.IE==8) ? '<i class="i-z0027unchecked"></i>' : params.svg.iconUnchecked;
				},
				tGroupId: function(){
					return mode+'_'+this.status.statusId+'_'+this.status.description+'_'+this.viewKey.transactionId;
				},
				tGroup: function(){
					return this.status.description;
				}
            };    
		},
		onRender: function() {
			
			if(yo.truth(params.switchEnableTags)) {  // if tag feature is ON
				 // render the tags section in accordion content
	            var tagNamesArr = this.model.get('tagNames');
	            for(i=0;i<tagNamesArr.length;i++) {
	                this.tags.add({tagName:tagNamesArr[i],transactionId:this.transId, container:'bank'});
	            }
	            this.getTagIconHtml();
            }
            this.getSearchDropdownHtml();
			
			return this;
		},
		addTagToMultipleTrans: function(tagValue){
			var transCheckBox = this.$('.multiSelectCheck');
			if(transCheckBox && transCheckBox[0].checked){
				this.checkAlreadyPresentTagOrAdd(tagValue);
	            this.updateTagHeader();
			}
        },
		openAccordion: function(e){
			yo.doAccordionToggle(e);					
		},
		closeOpenedAccordion: function(e){
			this.$('dd.accordion-navigation.active .accordionAnchor').trigger("click")
		},
		handleAttachAdd: function(e) {
			attach.addNewItem(e.currentTarget);
		},
		handleAttachAddMobile: function(e) {
			attach.addNewItem(e.currentTarget,"mobileSubtitleBordered");
		},

		handleAttachPreview: function(e) {
			attach.showPreview(e.currentTarget);
		},

		handleAttachRemove: function(e) {
			attach.removeItem(e.currentTarget);
		},
		
		selectTag: function(e){
			var name = $(e.target).html();
	        this.addTagInput = this.$("#newTag"); 
	        this.addTagInput.val(name);
	        $(document).foundation('dropdown', 'closeall');
	        
	        // remove the disabled class from save button
            if( this.$("#addTagModal").find('.saveTag') && this.$("#addTagModal").find('.saveTag').hasClass('disabled')) { 
            	this.$("#addTagModal").find('.saveTag').removeClass('disabled'); 
            }
            //check if save button is hidden : means its mobile view
	        if( this.$("#addTagModal").find('.saveTag').is(":hidden")  ){
	        	this.createOnEnter(e,true);
	        }
                    
		},

		updateTagHeader: function(){
			var tagCount = this.tags.length;
			if( tagCount > 0) {
			
				var lastTag = this.tags.at(tagCount-1);
				this.$("#tagHeader").html( '<div class="txnTagHeaderName">'+lastTag.get('tagName')+'</div>');
				if(tagCount-1 > 0) {
					this.$("#tagHeader").append('&nbsp;&amp;&nbsp;'+ (tagCount - 1) +' '+__["more"]);
				}
				this.$("#tagHeader").attr('title',lastTag.get('tagName'))	;
			}
			else {
				this.$("#tagHeader").html(null);
			}
			this.getTagIconHtml();
		},
		
		showAddTagDialogBox: function() {
		    
			//var tagPopupTmpl = templates['tagLightBox'];
            //this.$("#addTagModal").html(tagPopupTmpl({tId:this.txnId, action :'Add Tag'}));

            this.$("#addTagModal").find('label').html(__['Add Tag']); 
            //yo.popInsideLightBox(this.$("#addTagModal"));
            this.$("#addTagModal").addClass("white_content");
		    this.$(".black_overlay").show();
            
            this.addTagInput = this.$(".newTag");
            this.addTagInput.val(''); 
            this.addTagInput.focus();
            
		},
		closeLightBox : function(){
			this.$(".black_overlay").hide();
			this.$("#addTagModal").removeClass("white_content"); 
        	this.$("#addTagModal").removeClass('editTag');
        	this.$("#addTagModal").find('.saveTag').html(__['Add Tag']);
        	this.addTagInput.val(''); 
        	//this.updateCSS();
		},
		
		addTag: function(newTag) {
			var view = new TransactionTagView({model: newTag, parentView: this});
			this.$("#tagContainer").append(view.render().el);
		},
		
		showEditTagDialogBox: function(oldTag, oldTagView){
		    
		    this.$("#addTagModal").addClass('editTag');
		    //this.updateCSS();
		    
		    this.$("#addTagModal").find('label').html(__['Edit Tag']); 
		    this.$("#addTagModal").find('.saveTag').html(__['Save']);
		    this.$("#addTagModal").find('.saveTag').removeClass('disabled');
		    //yo.popInsideLightBox(this.$("#addTagModal"));
		    
		    this.$("#addTagModal").addClass("white_content");
		    this.$(".black_overlay").show();
		    
		    this.addTagInput = this.$("#newTag");
		    this.addTagInput.focus();
		    this.addTagInput.val(oldTag.get('tagName'));
		    this.oldTagView = oldTagView;
		},	
		
		createOnEnter: function(e,override) {
			var x = e.charCode || e.keyCode;  // Get the Unicode value
			if(x==8||x==46){
				return;//do not kill the backspace or delete events
			}else{
				var val = String.fromCharCode(x);
		    	if(yo.isJunk(val)){//keep out junk chars
					yo.endEvt(e);
					return;
				}
			}
		    this.addTagInput = this.$("#newTag");  
		    var tagValue = this.addTagInput.val();
		    var editTag = false;
		    // if no value entered
		    if (!$.trim(tagValue)) {
		    	this.resetRecentTagsDropdown();    
		    	if( this.$("#addTagModal").find('.saveTag')) { 
		    		this.$("#addTagModal").find('.saveTag').addClass('disabled'); 
		    	} 
		    	return;
		    }
            if (!yo.enter(e) &&e.type != "click"&&e.keyCode!=40) {
	 			
            	this.addTagInput.val(tagValue);
            	// remove the disabled class from save button
            	if( this.$("#addTagModal").find('.saveTag') && this.$("#addTagModal").find('.saveTag').hasClass('disabled')) { this.$("#addTagModal").find('.saveTag').removeClass('disabled'); }
                this.showTagAutoComplete(e.target); 
                return;
            }
            
            if(e.keyCode==40){//down arrow
            	this.$('#addTagModal').find('a')[0].focus();
            }
               
            // is user editing tag? 
            if( this.$("#addTagModal").hasClass('editTag')){
            	 editTag = true;
            }
            //close lightbox effect if present
            if($('.black_overlay').is(":visible") ){  // if mobile view or edit tag view
            	this.closeLightBox();
	            
            	// this.$("#addTagModal").removeClass('editTag');
            	// this.updateCSS();
            	
            }
            // show loading icon
            //this.$("#tagContainer"+this.txnId).append(loading icon);
            // call BE api for add tag
            // in call back function { // do the following} 
            $(document).foundation('dropdown', 'closeall'); 
            
            // reset add tag autocomplete dropdown
            this.resetRecentTagsDropdown(); 
            //delete old tag and clear its view
            if( editTag) {
                this.oldTagView.clear();
                this.oldTagView = null;
            }
            this.checkAlreadyPresentTagOrAdd(tagValue);
            
            // Take the focus away from input box to close mobile keyboard
			this.addTagInput.blur();
            this.addTagInput.val('');
            //if desktop
            this.addTagInput.focus();
            // add disabled class to save button
            if( this.$("#addTagModal").find('.saveTag')) { this.$("#addTagModal").find('.saveTag').addClass('disabled'); }
                               
            this.updateTagHeader();
		},
		checkAlreadyPresentTagOrAdd: function(tagValue){
			//check if tag is already present, if so, don't add it
            var alreadyPresentTag = this.tags.isPresent('tagName', tagValue); //Added logic to check case insensitive
            if( alreadyPresentTag && alreadyPresentTag.length == 0){                
                this.tags.add({tagName: tagValue, transactionId:this.transId,container:'bank'});
                TransactionCache.refreshTags();
            }		
		},
		
		setSuggestedTags: function(matches){
			var txnTags = this.tags; //this.model.get('tagNames');
			var found = false;
			this.suggestedTags = [];
			// get tags from allTags starting with given keyword
			
			if(matches.length>0){
				
				for(var i=0; i<matches.length; i++){
					for(var j=0; j<txnTags.length; j++){
						// make sure the suggested tag list doesn't include this txn tags
						if(matches[i].toLowerCase() === txnTags.at(j).get('tagName').toLowerCase()) {
							found = true;
						}							
					}
					if( found == false) {	
						this.suggestedTags.push(matches[i]) ;
						
					}
					found = false;
				}
			}
		},
		
		showTagAutoComplete:function(el){	
			//run query for autocomplete matches
			
			this.setSuggestedTags(TransactionCache.allTags);
            if(this.suggestedTags && this.suggestedTags.length>0){
				var lis = '';
				for(var i=0; i<this.suggestedTags.length; i++){			
					if(this.suggestedTags[i].toLowerCase().indexOf($(el).val().toLowerCase()) == 0) {
						var liEl = '<li><a href="#">'+this.suggestedTags[i]+'</a></li>';
						lis += liEl;
					}
				}		
				$("#TagDrop"+this.txnId).html(lis);
				var d= $("#TagDrop"+this.txnId);
				if(lis !=''){
					Foundation.libs.dropdown.open(d,this.$("#newTag"));
				}
				else{
					Foundation.libs.dropdown.close(d);
				}	
				//$("#TagDrop").addClass("open").addClass("bordered");
			}
		},


		resetRecentTagsDropdown : function() {
				var content = [];
				
				this.addTagInput = this.$("#newTag");  
		    	var tagValue = this.addTagInput.val();
		   
		    	if ($.trim(tagValue)) { 
		    		$("#TagDrop"+this.txnId).html(content.join(''));
		    		return;
		    	}
				// if no value entered
				this.setSuggestedTags(TransactionCache.recentTags);
               
                content.push(yo.getDropdownOptions(this.suggestedTags));
                    
				$("#TagDrop"+this.txnId).html(content.join(''));
				//Foundation.libs.dropdown.open($("#TagDrop"+this.txnId));				
				//$("#TagDrop"+this.txnId+" li").attr("onclick","yo.dropdownChangeElem(event,'"+this.addTagInput.attr('id')+"')");
				
		},
		
		getTagIconHtml : function(){
            var id = 'tagHeaderIcon';
            if(this.tags.length >= 1){
                this.$('#'+id).html((yo.IE==8) ?  '<i class="i-z0017tag"></i>': params.svg.tagIcon);
            }
            else {
                this.$('#'+id).html('');
            }
        },
        getSearchDropdownHtml : function(){
        	var tCategory = __[this.model.attributes['category'].categoryName];
        	
        	var attributes={
        				//data-attributes needed in the dropdown html for changing Category
						"categoryId":this.model.attributes['category'].categoryId,
						"categoryLevelId":this.model.attributes['category'].categoryLevelId,
						"containerType":this.model.attributes['viewKey'].containerType,
						"transactionId":this.model.attributes['viewKey'].transactionId
					};
			//old way that worked: 
			this.$('#dropdown' + this.txnId).html(yo.getDropdownHtml('dropdown' + this.txnId,yo.getDropdownOptions(params.categoryOptions), tCategory ,'yo.updateCategory', attributes,true));
			// but isn't fancy enough for them so now we are doing a differnet way each for mobile and desktop
			yo.addDropdownSearchEvents(this.$('#dropdown' + this.txnId),__["CATEGORY"],params.categoryOptions);
			
        	
        },
		
		onClose: function() {
	      _(this.childViews).each(function(view) {
	        	view.closeView();
	        	view= null;
	      });
	   },
		
	});
    
   
    return TransactionRowView;
	
});  
	



// DARK OVERLAY STUFF
var overlay = {};
overlay.defs = {
	count: 0,
	zIndexFloor: 10000,
	zIndexStep:  100,
	overlayModal: 'globalOverlayModal',
	overlayName:  'globalDarkOverlay',
	closeIconMarkup: "<a href='javascript:overlay.hide()' class='globalModalClose'>&times;</a>"
};
overlay.fixScroller = function () {
	var i, modal, windowHeight = $(window).height();
	for (i=overlay.defs.count; i>0; i--) {
		modal = document.getElementById(overlay.defs.overlayModal + i);
		if ($(modal).height() >= windowHeight) {
			modal.style.height = "100%";
		} else {
			modal.style.height = "auto";
		}
	}
};
overlay.modalShow = function (params, override) {
	/*	$params::
		default: set this to TRUE in params to force default modal
		new: true if new overlay atop existing overlay
		hookNode: ref to node where overlay to be inserted
		addContent: markup of modal contents
		addStyle: css style rules to attach to modal
		addClass: css class names to attach to modal
	*/

	// show new black overlay if first time modal or modal on top of existing modal $params.new==true
	if (overlay.defs.count === 0 || params['new'] === true) {
		var targetHookNode = overlay.defs.count === 0 ? params.hookNode : null;
		overlay.defs.count += 1;
		overlay.darkShow(targetHookNode);
	}

	// remove existing modal if !$params.new, new modal goes in its place
	var targetOldModalNode = document.getElementById(overlay.defs.overlayModal + overlay.defs.count);
	if (targetOldModalNode && params['new'] !== true) {
		$(targetOldModalNode).remove();
	}

if (override) {
	// TBD ?
	return;
}

	// modal node will be injected as last sibling of the target overlay node
	var targetHookForModal = document.getElementById(overlay.defs.overlayName + '1');
	var newModalNode = overlay.nodeConstructor(overlay.defs.overlayModal, 1);
	$(targetHookForModal.parentNode).append(newModalNode);

	if (params.addClass)   newModalNode.setAttribute('class', newModalNode.getAttribute('class') + ' ' + params.addClass);
	if (params.addStyle)   newModalNode.setAttribute('style', newModalNode.getAttribute('style') + ' ' + params.addStyle);
	if (params.addContent && params["default"]) {
		newModalNode.innerHTML = "<div class='globalModalBody'>" + params.addContent + overlay.defs.closeIconMarkup + "</div>";
	} else if (params.addContent) {
		newModalNode.innerHTML = params.addContent;
	}

	if (params.callback && params.callback.fn) {
		if (params.callback.timeout >= 0) {
			setTimeout(params.callback.fn,params.callback.timeout);
		} else {
			params.callback.fn();
		}
	}

	// 
//	overlay.fixScroller();
//	$(window).on("resize", overlay.fixScroller);
};
overlay.darkShow = function (targetRootNode) {
	var targetNode = document.getElementById(overlay.defs.overlayName + '1');
	var layer = overlay.nodeConstructor(overlay.defs.overlayName, 0);
//	$(layer).click(overlay.hide);
	if (targetRootNode !== null) { // if insertion target node is given
		$(targetRootNode).after(layer);
	} else if (targetNode) { // if new overlay goes atop existing overlay
		$(targetNode.parentNode).append(layer);
	}
};
overlay.nodeConstructor = function (layerName, indexOffset) {
	var zIndex  = indexOffset + overlay.defs.zIndexFloor + overlay.defs.zIndexStep * overlay.defs.count;
	var layer = document.createElement('DIV');
	layer.setAttribute('id',    layerName + overlay.defs.count);
	layer.setAttribute('class', layerName);
	layer.setAttribute('style','display:block;z-index:' + zIndex + ';');
	return layer;
};
overlay.hide = function () {
	$('#' + overlay.defs.overlayName  + overlay.defs.count).remove();
	$('#' + overlay.defs.overlayModal + overlay.defs.count).remove();
	overlay.defs.count -= 1;
	if (overlay.defs.coun===0) $(window).off("resize", overlay.fixScroller);
};
overlay.hideAll = function () {
	for(var i = overlay.defs.count; i > 0; i--) {
		$('#' + overlay.defs.overlayName  + i).remove();
		$('#' + overlay.defs.overlayModal + i).remove();
	}
	overlay.defs.count = 0;
	$(window).off("resize", overlay.fixScroller);
};


// ATTACHMENT RELATED STUFF

var attach = new Object();
attach.defs = {
	activeTxnId: null,
	activeAttachFilepath: null,
	activeAttachBoxId:  'activeAttachContainerBox',
	canvasContainerBox: 'canvasContainerBox',
	attachBoxCssName:   '.attachBox',
	attachItemCssName:  'attachItem', 
	darkOverlayName1:   'attachDarkOverlay1', 
	darkOverlayName2:   'attachDarkOverlay2', 
	darkOverContentId:  'attachDarkContent',
	mobileView: yo.width < 600,
	thumbnailSupport: window.File && window.FileReader && window.FileList && window.Blob,
	supportedFilesString: 'PDF, PNG, JPEG, and GIF',
	supportedFileTypes: ',PDF,PNG,GIF,JPEG,JPG,JPE,JIF,JFI,JFIF,',
	supportedFileSize: 5, // in MBs!!!
	errorIconLarge: params.svg.errorIconLarge,
	attachIconImage: params.svg.attachIconImage,
	attachIconDocument: params.svg.attachIconDocument
};
attach.clickEventDelegate = function (targetElement) {
	try {
		// proper modern dom3 delegation
		var evt = document.createEvent('MouseEvents');
		evt.initEvent('click', true, true);
		targetElement.dispatchEvent(evt);
	} catch (exception) {
		// fallback for ie8, nexus, etc
		targetElement.click();
	}
};
attach.resetFormData = function () {
	var activeAttachBox = $('#' + this.defs.activeAttachBoxId);
	var form = $(activeAttachBox).find("form[name=attach_item_form]").get(0);
	// cleanup file input field
	var oldFileInput = form['attach_item_file'];
	var newFileInput = document.createElement('INPUT');
		newFileInput.setAttribute('type',   oldFileInput.getAttribute('type'));
		newFileInput.setAttribute('name',   oldFileInput.getAttribute('name'));
		newFileInput.setAttribute('accept', oldFileInput.getAttribute('accept'));
	form.removeChild(oldFileInput);
	form.appendChild(newFileInput);
	// remove text areas that hold thumbnail data
	$(form).find("textarea").remove();
	// remove canvas 
	$(activeAttachBox).find('div.'+this.defs.canvasContainerBox).remove();
	// reset $activeAttachFilepath
	attach.defs.activeAttachFilepath = null;
};
attach.addNewItem = function (targetElement, parentContainer) {
	// obtain itemId
	var itemId = targetElement ? $(targetElement).attr('data-item-id') : false;
	if (!itemId) return;
	// set item id for global refs
	this.defs.activeTxnId = itemId;
	// ensure to remove previously set active id
	$('#' + this.defs.activeAttachBoxId).removeAttr('id');
	// identify active attach box with unique elem#id singleton
	var attachBoxElement = parentContainer ? $(targetElement).parents("."+parentContainer).find(this.defs.attachBoxCssName) : $(targetElement).parents(this.defs.attachBoxCssName);
	$(attachBoxElement).attr('id',this.defs.activeAttachBoxId);
	// invoke file input click
	var fileInputButton = $('#'+this.defs.activeAttachBoxId).find("input[name=attach_item_file]").get(0);
	this.clickEventDelegate(fileInputButton);
	// upon selection, initiate attachment processing & preparation
	$(fileInputButton).change(function(e){
		// prevents ineligible invocations when FileInput picker opened/closed many times prior w/o selection 
		// otherwise it will push all calls to queue and they all will fire upon proper file selection
		if (attach.defs.activeAttachFilepath != fileInputButton.value) {
			attach.defs.activeAttachFilepath  = fileInputButton.value;
			return attach.newItemHandler(e, fileInputButton.value);
		}
	});
};
attach.removeItem = function(targetElement) { // targetElement is polymorphic object of two distinct types
	var removalNode = $(targetElement).parents('.' + this.defs.attachItemCssName).get(0);
	var itemId    = removalNode ? $(removalNode).attr('data-item-id') : false;
	var elementId = removalNode ? $(removalNode).attr('id') : false;
	if (!itemId && !elementId) {
		// we arrive here when $this called from preview, thus $targetElement holds fully ready prepared data
		// this also means that proper $activeAttachBoxId is already set
		itemId    = targetElement.itemId;
		elementId = targetElement.elemId;
	} else {
		// set proper $activeAttachBoxId
		// identify active attach box with unique elem#id singleton
		$('#' + this.defs.activeAttachBoxId).removeAttr('id'); // ensure to remove previously set active id
		$(targetElement).parents(this.defs.attachBoxCssName).attr('id',this.defs.activeAttachBoxId);
	}
	if (!itemId || !elementId) return;
	// display removal confirmation prompt
	var viewModal = attach.modalViewPrepare('removalPrompt', {
		'elementId':elementId,
		'itemId':itemId
	});
	overlay.modalShow({
		'new':true,
		'hookNode': removalNode ? removalNode.parentNode : null,
		'addContent': viewModal['content'],
		'addClass': viewModal['classes'], 
		'addStyle': viewModal['styles']
	});
};
attach.removeItemCommit = function(dataObj) {
	var removalNode = $('#'+this.defs.activeAttachBoxId + ' #'+dataObj.elemId).get(0);
	// close all overlays
	overlay.hideAll();
	// exit if no $removalNode, some error happened
	if (!removalNode) return;
	// add removal animation class
	removalNode.setAttribute("class", this.defs.attachItemCssName + " itemDeleted");
	// perform actual removal
	setTimeout(function () {
		removalNode.parentNode.removeChild(removalNode);
	}, 500);
	// remove from memomry
	window.imFiles['tId'+dataObj.itemId][dataObj.elemId] = null;
};
attach.editDescription = function (dataObj) {
	var viewModal = attach.modalViewPrepare('editDescription', {
		'attachName':window.imFiles['tId'+dataObj.itemId][''+dataObj.elemId].description,
		'elementId':dataObj.elemId,
		'itemId':dataObj.itemId
	});
	overlay.modalShow({
		'new':true,
		'addContent': viewModal['content'],
		'addClass': viewModal['classes'],
		'addStyle': viewModal['styles'],
		'callback': {
			'timeout': 200,
			'fn': function () {
				var inputField = document.getElementById('attach_name_input_element');
				inputField.focus(); // iOS does not show keyboard, needs workaround
			}
		}
	});
};
attach.editDescriptionSave = function (dataObj) {
	var newDescription = document.getElementById('attach_name_input_element').value,
		oldDescription = window.imFiles['tId'+dataObj.itemId][''+dataObj.elemId].description;
	if (newDescription != oldDescription) {
		// update description in memory
		window.imFiles['tId'+dataObj.itemId][''+dataObj.elemId].description = newDescription;
		// update preview overlay box heading
		$('#attach_preview_title').html(newDescription);
		// update description under image thumbnail
		$('#'+this.defs.activeAttachBoxId).find('#' + dataObj.elemId +' .attachDescription').html(newDescription);
	}
	overlay.hide();
};
attach.downloadItem = function (dataObj) {
	alert('downloads original attachment');
};
attach.showPreview = function (targetElement) {
	var attachElement = $(targetElement).parents('.' + this.defs.attachItemCssName).get(0);
	var itemId    = attachElement ? $(attachElement).attr('data-item-id') : false;
	var elementId = attachElement ? $(attachElement).attr('id') : false;
	if (!itemId || !elementId) return;

	// identify active attach box with unique elem#id singleton
	$('#' + this.defs.activeAttachBoxId).removeAttr('id'); // ensure to remove previously set active id
	$(targetElement).parents(this.defs.attachBoxCssName).attr('id',this.defs.activeAttachBoxId);

	var imgSrc = attach.defs.mobileView ? window.imFiles['tId'+itemId][elementId].large : window.imFiles['tId'+itemId][elementId].full;
	var imgMarkup = "&nbsp";
	if (imgSrc) {
		imgMarkup = "<img class='attachPreviewImage' src='" + imgSrc + "' alt='' />";
	} else if (targetElement.innerHTML.toLowerCase().indexOf("<svg ") > -1) {
		imgMarkup = "<div class='attachPreviewSVG'>"+targetElement.innerHTML+"</div>";
	} else {
		imgMarkup = "<div class='attachPreviewOther'>"+targetElement.innerHTML+"</div>";
	}

	// display attachment
	var viewModal = attach.modalViewPrepare('preview', {
		'attachment':imgMarkup,
		'attachName':window.imFiles['tId'+itemId][elementId].description,
		'elementId':elementId,
		'itemId':itemId
	});
	overlay.modalShow({
		'new':true,
		'hookNode':$(attachElement).parents(attach.defs.attachBoxCssName),
		'addContent': viewModal['content'],
		'addClass': viewModal['classes'],
		'addStyle': viewModal['styles']
	});
};

attach.modalViewPrepare = function (view, optionalParamsObject) {
	var content = '', tmp, styles, classes;
	var nonMobileKwd = !attach.defs.mobileView ? 'NonMobile' : '';
	var thisOpts = optionalParamsObject === undefined ? {} : optionalParamsObject;
	var closeIconMarkup = "<a href='javascript:overlay.hide()' class='globalModalClose'>&times;</a>";
	var viewHelper = {
		'tableRow': function (rowClassname, cellContent) {
			return	"<tr class='" + rowClassname + "'><td>" + cellContent + "</td></tr>";
		},
		'editDescriptionForm': function (strLabel, thisOpts) {
			var saveAction = "javascript:attach.editDescriptionSave({itemId:\""+ thisOpts.itemId +"\",elemId:\""+ thisOpts.elementId +"\"});";
			return	"<form onsubmit='" + saveAction + "return false' class='attachAddEditForm'>" + 
					"	<h4><label for='attach_name_input_element'>"+ strLabel +":</label></h4>" +
					"	<div>" +
					"	<div class='sideBySideLong'><input id='attach_name_input_element' type='text' name='attach_name' value='" + thisOpts.attachName + "' /></div>" +
					"	<div class='sideBySideShortRight'><a class='button' href='" + saveAction + "'>Save</a></div>" +
					"	</div>" + 
					"</form>";
		},
		'errorMessage': function (errorType) {
			var type = errorType || 'default',
				error= {},
				errorIcon = "<div class='iconErrorAlertLarge'>" + attach.defs.errorIconLarge + "</div>";
				error['default'] 		 = errorIcon + "<h5>We're sorry. An unexpected error occurred.</h5>";
				error['file_size_error'] = errorIcon + "<h5>File is too big. "+ attach.defs.supportedFileSize +" MB max.</h5>";
				error['file_type_error'] = errorIcon + "<h5>File type is not supported.</h4><p>Supported file types are: "+ attach.defs.supportedFilesString +".</p>";
			return error[type];
		}
	};

	var markup = {
		'uploadProgress': {
			'stylesNonMobile': 'width:300px;',
			'content':	"<h5>Uploading Attachment</h5>" + 
						"<div>[progress bar] %</div>"
		},
		'uploadSuccess': {
			'stylesNonMobile': 'width:600px;',
			'heading':	"<h4 class='overlayLightupHeading'><span>Upload Successful!</span></h4>",
			'content':	viewHelper.editDescriptionForm('Attachment Name', thisOpts)
		},
		'errorDisplay': {
			'stylesNonMobile': 'width:300px;',
			'content':	viewHelper.errorMessage(thisOpts.errorType) + 
						"<div class='clearfix'>" +
						"<a class='button ofSameSize left'  href='javascript:overlay.hide()'>Try Again</a>" +
						"<a class='button ofSameSize right secondary' href='javascript:overlay.hideAll()'>Cancel</a>" + 
						"</div>"
		},
		'editDescription': {
			'stylesNonMobile': 'width:600px;',
			'content':	viewHelper.editDescriptionForm('Edit Name', thisOpts)
		},
		'removalPrompt': {
			'classes': 'promptConfirmation global-modal',
			'classesNonMobile': '',
			'stylesNonMobile': '',
			'content':	"<h5>Are you sure you want to delete the attachment from this transaction?</h5>" + 
						"<div class='clearfix'>" +
						"<a class='button ofSameSize warning left'    href='javascript:attach.removeItemCommit({itemId:\""+ thisOpts.itemId +"\",elemId:\""+ thisOpts.elementId +"\"})'>Delete</a>" +
						"<a class='button ofSameSize secondary right' href='javascript:overlay.hide()'>Cancel</a>" + 
						"</div>"
		},
		'preview': {
			'tabledPreview': true,
			'classes':	"attachmentPreviewModal",
			'styles':	"width:100%;height:100%;",
			'boxTop':   "<a class='button right' href='javascript:attach.editDescription({itemId:\""+ thisOpts.itemId +"\",elemId:\""+ thisOpts.elementId +"\"})'>Edit</a>" + 
						"<h4 id='attach_preview_title'>"+ thisOpts.attachName + "</h4>",
			'boxBottom':"<div class='attachPreviewActions clearfix'>" + 
						"	<a class='button ofSameSize left'        href='javascript:attach.downloadItem({itemId:\""+ thisOpts.itemId +"\",elemId:\""+ thisOpts.elementId +"\"})' download>Download</a>" + 
						"	<a class='button ofSameSize right warning' href='javascript:attach.removeItem({itemId:\""+ thisOpts.itemId +"\",elemId:\""+ thisOpts.elementId +"\"})'>Delete</a>" +
						"</div>",
			'content':  thisOpts.attachment
		}		
	}

	// prepare body content for modal
	if (markup[view]['tabledPreview']) {
		content += "<table class='overlayTable'>";
		if (markup[view]['boxTop'+nonMobileKwd]!=undefined ? markup[view]['boxTop'+nonMobileKwd] : markup[view]['boxTop']) {
			content += viewHelper.tableRow( 'overlayTableTop', markup[view]['boxTop'+nonMobileKwd]!=undefined ? markup[view]['boxTop'+nonMobileKwd] : markup[view]['boxTop'] );
		}
			tmp = markup[view]['content'+nonMobileKwd]!=undefined ? markup[view]['content'+nonMobileKwd] : markup[view]['content'];
			content += viewHelper.tableRow( 'overlayTableMiddle', "<div class='overlayTableContent'>" + tmp + "</div>" );
		if (markup[view]['boxBottom'+nonMobileKwd]!=undefined ? markup[view]['boxBottom'+nonMobileKwd] : markup[view]['boxBottom']) {
			content += viewHelper.tableRow( 'overlayTableBottom', markup[view]['boxBottom'+nonMobileKwd]!=undefined ? markup[view]['boxBottom'+nonMobileKwd] : markup[view]['boxBottom'] );
		}
		content += "</table>";
		content +=  closeIconMarkup;
	} else {
		if (markup[view]['heading'+nonMobileKwd]!=undefined ? markup[view]['heading'+nonMobileKwd] : markup[view]['heading']) {
			content += markup[view]['heading'+nonMobileKwd]!=undefined ? markup[view]['heading'+nonMobileKwd] : markup[view]['heading'];
		}
		content += "<div class='globalModalBody'>";
		content += 		markup[view]['content'+nonMobileKwd]!=undefined ? markup[view]['content'+nonMobileKwd] : markup[view]['content'];
		content += 		closeIconMarkup;
		content += "</div>";
	}


	// if any, add extra css classes or styles for modal
	styles  = markup[view]['styles'+nonMobileKwd]!=undefined  ? markup[view]['styles' +nonMobileKwd] : markup[view]['styles'];
	classes = markup[view]['classes'+nonMobileKwd]!=undefined ? markup[view]['classes'+nonMobileKwd] : markup[view]['classes'];
	if (attach.defs.mobileView) {
		if (classes==undefined) classes = 'mobileView';
		else classes += ' mobileView';
	}

	return {
		'content': content, 
		'classes': classes,
		'styles':  styles
	}
}











attach.defs.canvas = {
	kind: {
		small: {
			id: 'attach_base64_small',
			width: 75,
			height:75,
			finalOffsetX:-20,
			finalOffsetY:-10,
			zoomRatio:1.5
		},
		large: {
			id: 'attach_base64_large',
			width: 300,
			height:300,
			finalOffsetX:0,
			finalOffsetY:0,
			zoomRatio:1
		},
		full: {
			id: 'attach_base64_full',
			width: 500,
			height:500,
			finalOffsetX:0,
			finalOffsetY:0,
			zoomRatio:1
		}
	},
	initOffsetX:0,
	initOffsetY:0,
	scaleRatio:1,
	imgQuality:0.8,
	portrait:true
}

attach.saveToLocalMem = function (itemId, form) {
	var thumbnail = attach.defs.canvas.kind;
	window.imFiles = window.imFiles || [];
	if (!window.imFiles['tId'+attach.defs.activeTxnId]) {
		window.imFiles['tId'+attach.defs.activeTxnId] = [];
	}
	window.imFiles['tId'+attach.defs.activeTxnId][itemId] = {
		description: form['attach_item_name'].value
		,small: form[thumbnail.small.id] ? form[thumbnail.small.id].value : undefined
		,large: form[thumbnail.large.id] ? form[thumbnail.large.id].value : undefined
		,full:  form[thumbnail.full.id]  ? form[thumbnail.full.id].value  : undefined
	}
	return;
};
attach.saveToRemoteStorage = function (itemId) {
	/*
	// perform save operation
	var form = $('#'+attach.defs.activeAttachBoxId).find('form[name=attach_item_form]').get(0);
	var formDataString = $(form).serialize();
	$.ajax({
		type: "POST",
		enctype:'multipart/form-data',
		cache: false,
		url: "http://192.168.201.9/timely/",
		data: formDataString,
		dataType: "json",
		processData: false,
		contentType: false,
		success: function(data) {
			//var obj = jQuery.parseJSON(data);
			alert('post success');
		},
		error: function(){
			alert('post error');
		}
	});
	*/

	// display upload successful message
	var viewModal = attach.modalViewPrepare('uploadSuccess',{
		'attachName':window.imFiles['tId'+attach.defs.activeTxnId][itemId].description,
		'elementId': itemId,
		'itemId':    attach.defs.activeTxnId
	});
	overlay.modalShow({
		'addContent': viewModal['content'],
		'addClass':   viewModal['classes'],
		'addStyle':   viewModal['styles']
	});
	// cleanup form 
	attach.resetFormData();
	return;
};
attach.displayNewAttach = function (itemId, thumbnail) {
	var attachMarkup = "N/A";
	if (window.imFiles['tId'+attach.defs.activeTxnId][itemId].small) {
		attachMarkup = '<img src="' + window.imFiles['tId'+attach.defs.activeTxnId][itemId].small + '" alt="" />';
	} else if (thumbnail) { // fallback to default icon if provided
		attachMarkup = thumbnail;
	}
	var newAttach = document.createElement('DIV');
	newAttach.setAttribute('class', attach.defs.attachItemCssName);
	newAttach.setAttribute('id', itemId);
	newAttach.setAttribute('data-item-id', attach.defs.activeTxnId);
	newAttach.innerHTML =   '<a href="#">' + attachMarkup + '</a> ' + 
							'<span class="attachDescription">' + window.imFiles['tId'+attach.defs.activeTxnId][itemId].description + '</span>' + 
							'<b class="attachDeleteIcon">&times;</b>';
	$(newAttach).insertBefore($('#'+attach.defs.activeAttachBoxId).find('.attachBtn'));
	return;
};
attach.newItemHandler = function (e, fileName) {
	var attachBox = $('#'+this.defs.activeAttachBoxId);
	var fileType = fileName.substring(fileName.lastIndexOf('.')+1).toUpperCase();
	var fileTypeIcon = fileType=='PDF' ? attach.defs.attachIconDocument : attach.defs.attachIconImage;


	// if file type is NOT supported, then display error message and exit
	if (fileName && fileName.length > 0 && attach.defs.supportedFileTypes.indexOf(',' + fileType +',') == -1) {
		var viewModal = attach.modalViewPrepare('errorDisplay',{
			'errorType':'file_type_error'
		});
		overlay.modalShow({
			'new': true,
			'hookNode':   attachBox,
			'addContent': viewModal['content'],
			'addStyle':   viewModal['styles']
		});
		attach.resetFormData();
		return;
	}

	// if file EXCEEDS size limit, then display error message and exit
	if (e.target && e.target.files[0] && e.target.files[0].size > attach.defs.supportedFileSize * 1024 * 1024) {
		var viewModal = attach.modalViewPrepare('errorDisplay',{
			'errorType':'file_size_error'
		});
		overlay.modalShow({
			'new': true,
			'hookNode':   attachBox,
			'addContent': viewModal['content'],
			'addStyle':   viewModal['styles']
		});
		attach.resetFormData();
		return;
	} else {
		// TODO file size checker for IE8/9 via activex
	}

	// display uploading modal
	var viewModal = attach.modalViewPrepare('uploadProgress');
	overlay.modalShow({
		'new':true,
		'hookNode':   attachBox,
		'addContent': viewModal['content'],
		'addStyle':   viewModal['styles']
	});

	// handle upload for HTML5 NO-support browsers
	if (!attach.defs.thumbnailSupport) {

		var attachForm = $('#'+attach.defs.activeAttachBoxId).find('form[name=attach_item_form]').get(0);
		var randAttachId = "attachId" + (new Date()).getTime();

		/*  Simulate uploaded stuff  */
		attach.saveToLocalMem(randAttachId, attachForm);
		attach.saveToRemoteStorage(randAttachId);
		attach.displayNewAttach(randAttachId, fileTypeIcon);

		return;
	}

	// handle upload of NON-IMAGE on HTML5 YES-supported browsers
	if (fileType=='PDF') {
		var attachForm = $('#'+attach.defs.activeAttachBoxId).find('form[name=attach_item_form]').get(0);
		var randAttachId = "attachId" + (new Date()).getTime();

		/*  Simulate uploaded stuff  */
		attach.saveToLocalMem(randAttachId, attachForm);
		attach.saveToRemoteStorage(randAttachId);
		attach.displayNewAttach(randAttachId, fileTypeIcon);

		return;
	}

	// proceed to handle IMAGE upload on HTML5 YES-supported browsers

	var URL = window.webkitURL || window.URL;
	var url = URL.createObjectURL(e.target.files[0]);
	var img = new Image();

	img.onload = function() {

		var canvas = $(attachBox).find("canvas").get(0);
		if (!canvas) {
			$(attachBox).append("<div class='" + attach.defs.canvasContainerBox + " removeFromView'><canvas width='1' height='1'></canvas></div>");
			canvas = $(attachBox).find("canvas").get(0);
		}
		var ctx = canvas.getContext("2d");
		var canvasParams = attach.defs.canvas;

		var attachForm = $('#'+attach.defs.activeAttachBoxId).find('form[name=attach_item_form]').get(0);
		var randAttachId = "attachId" + (new Date()).getTime();

		canvasParams.portrait = img.width <= img.height;
		canvasParams.scaleRatio = canvasParams.portrait ? img.height/img.width : img.width/img.height;

		// generate thumbnails
		createAttachThumbnail(attachForm, ctx, img, canvas, canvasParams, "small");
		createAttachThumbnail(attachForm, ctx, img, canvas, canvasParams, "large");
		createAttachThumbnail(attachForm, ctx, img, canvas, canvasParams, "full");

		/*  Simulate uploaded stuff  */
		attach.saveToLocalMem(randAttachId, attachForm);
		attach.saveToRemoteStorage(randAttachId);
		attach.displayNewAttach(randAttachId);

	};
	img.onerror = img.onabort = function () {
		attach.resetFormData();
		// display upload error
		var viewModal = attach.modalViewPrepare('errorDisplay');
		overlay.modalShow({
			'addContent': viewModal['content'],
			'addStyle':   viewModal['styles']
		});
	};
	img.src = url;

    /*
    $("#save").click(function(){
        var html="<p>Right-click on image below and Save-Picture-As</p>";
        html+="<img src='"+canvas.toDataURL()+"' alt='from canvas'/>";
        var tab=window.open();
        tab.document.write(html);        
    });
    */
};
var createAttachThumbnail = function (targetForm, ctx, img, canvas, cParams, imgKind) {
	// calculate width and height, note if any edge is smaller than expected size
	var width = img.width < cParams.kind[imgKind].width  ? img.width : cParams.kind[imgKind].width;
	var height= img.height< cParams.kind[imgKind].height ? img.height: cParams.kind[imgKind].height;
	var scale = img.width < cParams.kind[imgKind].width && img.height< cParams.kind[imgKind].height ? 1 : cParams.scaleRatio; 
	canvas.width = width;
	canvas.height= height;
	// canvas offset coordinates
	var initX = cParams.initOffsetX;
	var initY = cParams.initOffsetY;
	// calculate dimensions of scaled image
	var modWidth = cParams.portrait ? width * cParams.kind[imgKind].zoomRatio : width * cParams.kind[imgKind].zoomRatio * scale;
	var modHeight= cParams.portrait ? height * cParams.kind[imgKind].zoomRatio * scale : height * cParams.kind[imgKind].zoomRatio;
	// image offset coordinates when superimposed atop canvas
	var finalX= cParams.kind[imgKind].finalOffsetX * cParams.kind[imgKind].zoomRatio;
	var finalY= cParams.kind[imgKind].finalOffsetY * cParams.kind[imgKind].zoomRatio;
	// center image offsets
	if ( cParams.portrait && scale != 1 && cParams.kind[imgKind].zoomRatio == 1) {
		finalY = (modWidth - modHeight) / 2;
	}
	if (!cParams.portrait && scale != 1 && cParams.kind[imgKind].zoomRatio == 1) {
		finalX = (modHeight - modWidth) / 2;
	}

	
	drawImageIOSFix(ctx, img, initX, initY, img.width, img.height, finalX, finalY, modWidth, modHeight);
	//ctx.drawImage(img,0,0,img.width,img.height,0,0,200,200);
	/*
	 * canvas.width=img.width;
	 * canvas.height = img.height;
	 * ctx.drawImage(img,0,0);
	 */

	// $("#dataImage").html("height: "+canvas.height +"\nwidth: "+canvas.width);

	var imageData = canvas.toDataURL("image/png", cParams.imgQuality);
	var newNode = document.createElement('TEXTAREA');
	newNode.name = cParams.kind[imgKind].id;
	newNode.value = imageData;
	/* THIS LINE THROWS EXCEPTION when select/cancel image multiple times w/o proceed, and then finally proceed */
	targetForm.appendChild(newNode);
	 
//	newImg.src = thumbImage;
//	var form = document.getElementById(cParams.formId);
//	form.appendChild(newImg);

/*	
	$("#dataImage").html(canvas.toDataURL());
	$("#imiA").attr("src",canvas.toDataURL());
	$("#imiB").attr("src",);
*/
	// $("#imiBsize").html("Size: " + canvas.toDataURL("image/png", cParams.imgQuality).length);
}

// experimental fix from stackoverflow

/**
 * Detecting vertical squash in loaded image.
 * Fixes a bug which squash image vertically while drawing into canvas for some images.
 * This is a bug in iOS6 devices. This function from https://github.com/stomita/ios-imagefile-megapixel
 * 
 */
function detectVerticalSquash(img) {
    var iw = img.naturalWidth, ih = img.naturalHeight;
    var canvas = document.createElement('canvas');
    canvas.width = 1;
    canvas.height = ih;
    var ctx = canvas.getContext('2d');
    ctx.drawImage(img, 0, 0);
    var data = ctx.getImageData(0, 0, 1, ih).data;
    // search image edge pixel position in case it is squashed vertically.
    var sy = 0;
    var ey = ih;
    var py = ih;
    while (py > sy) {
        var alpha = data[(py - 1) * 4 + 3];
        if (alpha === 0) {
            ey = py;
        } else {
            sy = py;
        }
        py = (ey + sy) >> 1;
    }
    var ratio = (py / ih);
    return (ratio===0)?1:ratio;
}

/**
 * A replacement for context.drawImage
 * (args are for source and destination).
 */
function drawImageIOSFix(ctx, img, sx, sy, sw, sh, dx, dy, dw, dh) {
    var vertSquashRatio = detectVerticalSquash(img);
 // Works only if whole image is displayed:
//  ctx.drawImage(img, sx, sy, sw, sh, dx, dy, dw, dh / vertSquashRatio);
 // The following works correct also when only a part of the image is displayed:
 
    ctx.drawImage(img, sx * vertSquashRatio, sy * vertSquashRatio, sw * vertSquashRatio, sh * vertSquashRatio, dx, dy, dw, dh );
}

;
/**
 * Responsible for rendering the Transactions list 
 * Including list for Past, Now, Future and search results
 * Call to yo.when to timeout till backbone loads
 * yo.when is in base.js 
 * @param {Backbone} loading backbone modules
 * @param {TransactionsCollection} loading the Collections module of Transactions
 * init like so: 
 * var listView = new TransactionsListView({_thisView.mode:"now", _thisView.divId:"some_thisView.divId", keyword:"somekeyword"});
 * passed in args can be accessed in this.options
 */

 define('10003507_js/views/TransactionTimeFilterView',[ '10003507_js/compiled/finappCompiled','10003507_js/views/TransactionListView'], function( templates,TransactionListView) { 
     
    
 	var TransactionTimeFilterView = Backbone.Marionette.ItemView.extend({

       
        template: templates['transactionTimeFilter'],
        tagName: 'div',    
        
        events: {
            "click .tabs li a"  : "filterTransactions",

        },
        initialize: function(){      
            
            this.moduleKey = this.options.moduleKey;  
            this.mode = this.options.mode;
        },   

        templateHelpers : function(){
		    var mode = this.options.mode;
		    return {
    		    displayFilters: function() { if( mode == 'past' || mode =='future'){return 'block';} return 'none';}
    		};    
        },
        
		filterTransactions: function(e) {
            
            var toDate = moment()
            ,fromDate = moment()
            ,elem = (e.target)?e.target:e.srcElement
            ,filter = elem.id;
            
            if(this.mode=='past'){
        		switch(filter){
        			case '1m':
        			fromDate = moment();
        			fromDate = fromDate.month(fromDate.month()-1);
        			toDate = moment();
        			break;
        			case '3m':
        			fromDate = moment();
        			fromDate = fromDate.month(fromDate.month()-3);
        			toDate = moment();
        			break;
        			case '6m':
        			fromDate = moment();
        			fromDate = fromDate.month(fromDate.month()-6);
        			toDate = moment();
        			break;
        			case '1y':
        			fromDate = moment();
        			fromDate = fromDate.year(fromDate.year()-1);
        			toDate = moment();
        			break;
        			case '2y':
        			fromDate = moment();
        			fromDate = fromDate.year(fromDate.year()-2);
        			toDate = moment();
        			break;
        			default:
        			fromDate = moment();
        			fromDate = fromDate.month(fromDate.month()-1);
        			toDate = moment();
        		}
            }else{
        		switch(filter){
        			case '1m':
        			fromDate = moment();
        			fromDate = fromDate.month(fromDate.month()+1);
        			toDate = moment();
        			break;
        			case '3m':
        			fromDate = moment();
        			fromDate = fromDate.month(fromDate.month()+3);
        			toDate = moment();
        			break;
        			case '6m':
        			fromDate = moment();
        			fromDate = fromDate.month(fromDate.month()+6);
        			toDate = moment();
        			break;
        			case '1y':
        			fromDate = moment();
        			fromDate = fromDate.year(fromDate.year()+1);
        			toDate = moment();
        			break;
        			case '2y':
        			fromDate = moment();
        			fromDate = fromDate.year(fromDate.year()+2);
        			toDate = moment();
        			break;
        			default:
        			fromDate = moment();
        			fromDate = fromDate.month(fromDate.month()+1);
        			toDate = moment();
        		}
            }
			
			filter = new yo.TransactionFilter();
			filter.set({mode:this.options.mode});
			filter.set({fromDate: fromDate.valueOf()});
		    filter.set({toDate: toDate.valueOf()});
		    if( this.options.mode == 'past')
				Application.Appcore.loadModule({ mode:filter, moduleKey : "10003204_10003507", moduleId : '10003507', el:'#scheduledTransactions', region :'#scheduledTransactions', divId:'#scheduledTransactions'});
			else if( this.options.mode == 'future')
				Application.Appcore.loadModule({ mode:filter, moduleKey : "10003204_10003507", moduleId : '10003507', el:'#postedTransactions', region :'#postedTransactions', divId:'#postedTransactions'});
			// whats the default container?? TODO
        },
		
		onClose: function() {
	      _(this.childViews).each(function(view) {
	        	view.closeView();
	        	view= null;
	      });
	   },
		
 	});
 	
	return TransactionTimeFilterView;
	
});

/**
 * Responsible for rendering the Transactions list 
 * Including list for Past, Now, Future and search results
 * Call to yo.when to timeout till backbone loads
 * yo.when is in base.js 
 * @param {Backbone} loading backbone modules
 * @param {TransactionsCollection} loading the Collections module of Transactions
 * init like so: 
 * var listView = new TransactionsListView({_thisView.mode:"now", _thisView.divId:"some_thisView.divId", keyword:"somekeyword"});
 * passed in args can be accessed in this.options
 */

 define('10003507_js/views/TransactionListView',[ '10003507_js/compiled/finappCompiled','10003507_js/views/TransactionRowView','10003507_js/views/TransactionTimeFilterView','10003507_js/models/TransactionCache'], function( templates,TransactionRowView,TransactionTimeFilterView,TransactionCache) { 
     
    
 	var TransactionListView = Backbone.Marionette.CompositeView.extend({

        template: templates['transactionList'],
        childView: TransactionRowView,
        childViewOptions : function () { return { myParent: this, mode : this.mode, isSearchView: this.options.mode == 'search' || this.options.mode == 'tag_search' }; },//passing options to child views
        tagName: 'div',    
        
        events: {
            'scroll #transactionlist': 'loadMore' ,
            "click .addTag"  : "resetRecentTagsDropdown",
            "tap   .addTag"  : "resetRecentTagsDropdown",
            "keyup .addTag"  : "addTagToSelectedTrans",
            "keyup .saveTag" :function(e){//this is the outer one in desktop mode
            	yo.endEvt(e);
            	if(yo.enter(e)){
            		this.addTagToSelectedTrans(e);
            	}
            },
			"click .saveTag"  : "addTagToSelectedTrans",
			"click .saveTagLink": "addTagToSelectedTrans",
			"click .sub-title ul li": 'selectTag',
			"click .accordion-navigation .multiSelectCheck": function(e){
				this.changeCheckboxIcon(e.currentTarget);
				this.showHideAddTagTextbox(e);
				this.checkSelectAllStatus(e);
			},
			"keyup .accordion-navigation .multiSelectCheck" :function(e){
				if(yo.enter(e)){
					this.changeCheckboxIcon(e.currentTarget);
					this.showHideAddTagTextbox(e);
					this.checkSelectAllStatus(e);
				}
			},
			"click #selectAllTrans": 'selectAllTransaction',
			"keyup #selectAllTrans" :function(e){
				if(yo.enter(e)){
					this.selectAllTransaction(e);
				}
			},
			"click .groupByStatus": 'selectGroupedTransactions',
			"keyup .groupByStatus" :function(e){
				if(yo.enter(e)){
					this.selectGroupedTransactions(e);
				}
			},
			"click .groupByDate": 'selectDateGroupedTransactions',
			"keyup .groupByDate" :function(e){
				if(yo.enter(e)){
					this.selectDateGroupedTransactions(e);
				}
			},
			"click .topMsgCtr .closeBtn": 'closeSuccessMsg',
			"click .editTrans" : 'showMultiselectCheckbox',
			"click .addTagsCtr .addTagButton": 'showMobileAddTagTextbox',
			"click .inputTitle .close": 'closeLightbox'
        },
        initialize: function(){      
            
            this.moduleKey = this.options.moduleKey;  
            this.mode = this.options.mode;
            yo.openAccordionMsg = __["Hide transaction details"];
            yo.closedAccordionMsg = __["Show transaction details"];
        },
        closeConfirmation: function(){
        	$(".global-modal").removeClass("white_content");
        	$(".black_overlay_del").hide();
        },
 		loadMore: function(){
           //console.log('calling loadmore ');
        },
        attachHtml: function(collectionView, itemView){
            //console.log('now showing===',itemView.model);
            var unCheckedCheckbox = (yo.IE==8) ? '<i class="i-z0027unchecked"></i>' : params.svg.iconUnchecked;
            
            if( this.options.mode != 'search' && this.options.mode != 'tag_search') {
                var dateHeader = moment(itemView.model.get('transactionDate'));
                var statusCheckboxMode = itemView.model.get("status").statusId+'_'+itemView.model.get("status").description;
                var dateCheckboxMode = itemView.model.get("status").statusId+'_'+itemView.model.get("status").description+'_'+'dateGroup_'+dateHeader.format('MMDDYYYY');
                var tGroup = itemView.model.get("status").description;
                var tDate = dateHeader.format('MMDDYYYY');
                
                var notPostedTxn = __[itemView.model.get("status").description] != __['Posted'] ? "tonneddown":"";
                if(itemView.model.get('showStatusHeader')) {
                    collectionView.$('#'+this.mode+'_transactionlist').append('<div class="sub-title-dark '+ notPostedTxn +'"><span class="checkboxCtr multiSelectCheck groupByStatus" id="'+statusCheckboxMode+'" role="checkbox" tabindex="0">'+ unCheckedCheckbox + '<span class="ada-offscreen">'+__["Select all"]+' '+__[itemView.model.get("status").description]+' '+__["Transactions"]+'</span></span>'+__[itemView.model.get("status").description]+'</div>');
                }
                if(itemView.model.get('showDateHeader')) {
                	// show running balance on dateheader only in account details page
                	if( this.options.mode == 'account' && tGroup == 'scheduled') {
                		//show running balance only for bank container
                		if( this.options.accountId && this.options.accountId.split('_')[2] && this.options.accountId.split('_')[2].match(/^(BANK|bank|banking)$/)) {
	                		var runningBalance = '<span class="textBalance">'+__["Balance : "]+'</span><span class="textBalanceWide">'+__["Projected Balance : "]+'</span>'+yo.money(parseFloat(itemView.model.get('runningBalance')),'',false);
	                		collectionView.$('#'+this.mode+'_transactionlist').append('<div class="sub-title-light '+ notPostedTxn +'"><span class="checkboxCtr multiSelectCheck groupByDate" tgroup="'+tGroup+'" tDate="'+tDate+'" id="'+dateCheckboxMode+'" role="checkbox" tabindex="0"">'+ unCheckedCheckbox +'<span class="ada-offscreen">'+__["Select all transactions dated"]+' '+dateHeader.format('MMMM DD')+' '+dateHeader.format('YYYY')+'</span></span>'+dateHeader.format('MMMM DD')+'<span class="trans-year-text">, '+dateHeader.format('YYYY')+'</span><span class="lmargin-15-per">'+runningBalance+'</span></div>');
	                	}
	                	else {
                    		collectionView.$('#'+this.mode+'_transactionlist').append('<div class="sub-title-light '+ notPostedTxn +'"><span class="checkboxCtr multiSelectCheck groupByDate" tgroup="'+tGroup+'" tDate="'+tDate+'" id="'+dateCheckboxMode+'" role="checkbox" tabindex="0">'+ unCheckedCheckbox +'<span class="ada-offscreen">'+__["Select all transactions dated"]+' '+dateHeader.format('MMMM DD')+' '+dateHeader.format('YYYY')+'</span></span>'+dateHeader.format('MMMM DD')+'<span class="trans-year-text">, '+dateHeader.format('YYYY')+'</span></div>');
                    	}	
                	}
                	else {
                    	collectionView.$('#'+this.mode+'_transactionlist').append('<div class="sub-title-light '+ notPostedTxn +'"><span class="checkboxCtr multiSelectCheck groupByDate" tgroup="'+tGroup+'" tDate="'+tDate+'" id="'+dateCheckboxMode+'" role="checkbox" tabindex="0">'+ unCheckedCheckbox +'<span class="ada-offscreen">'+__["Select all transactions dated"]+' '+dateHeader.format('MMMM DD')+' '+dateHeader.format('YYYY')+'</span></span>'+dateHeader.format('MMMM DD')+'<span class="trans-year-text">, '+dateHeader.format('YYYY')+'</span></div>');
                    }	
                }
            }
            
            itemView.$el.addClass(notPostedTxn);
            collectionView.$('#'+this.mode+'_transactionlist').append(itemView.el);
        },
       	
    
       	renderHtmlForTagSearch: function(){
       		var that = this;
       		
       		$("#appendedSearchResultsContainer .editTrans").on("click", function(e){
				that.showMultiselectCheckbox(e);
			});
			
       		$("#selectAllTagTrans").on("click", function(e){
 				that.selectAllSearchTagTransaction();//copied from selectAllSearchTransaction
 			});

			$("#editTagBtn").on("click", function(e){
 				
 				if($('#editDeleteTagHeader').hasClass('disabled')){return;}
				yo.modal = document.createElement('div');
				
				
				yo.modal.innerHTML = ' <div class="black_overlay" id="black_overlay_editTag" style="display: block;"><div role="button" tabindex="0" class="close-lightbox" title="Close Dialog" onclick="yo.NG.closeLightBox()">'+params.svg.cancelIcon+'</div></div><div id="editTagModal" class="TagModal addTagModal editTag white_content">\
					<form action="." onsubmit="return false;">\
						<label for="newTag">'+__["EDIT"]+' '+__["TAG"]+'</label>\
						<div class="clearfix">\
							<div class="sideBySideLong" style="margin;0 auto;">\
								<input tabindex="0" type="text" id="editTagSearch" class="newTag" maxlength="40" title="Edit tag." placeholder="'+__["Edit Tag"]+'" onkeypress="if(yo.enter(event)){yo.NG.editTagSave();}if(event.keyCode==9){yo.endEvt(event);$(this.parentNode.parentNode).find(\'.saveTag\')[0].focus();return;}var x=event.charCode||event.keyCode;var val=String.fromCharCode(x);if(yo.isJunk(val)){yo.endEvt(event);}">\
							</div>\
							<div class="sideBySideShortRight button desktop" role="button" tabindex="0" class="saveTag button" aria-label="Save tag" onclick="yo.NG.editTagSave()">'+__["Save"]+'\
							</div>	\
						</div>\
					</form>\
					<span class="ada-offscreen" onblur="yo.rotateDialogFocus($(this.parentNode.parentNode).find(\'.black_overlay\')[0],event);" onkeydown="yo.rotateDialogFocus($(this.parentNode.parentNode).find(\'.black_overlay\')[0],event);" tabindex="0" focusable="true">'+__["End of dialog content"]+'</span>\
				</div>';
				
				
				$('#body-content-js')[0].appendChild(yo.modal);
				$("#editTagSearch").focus();
				
				$($(".black_overlay")[0]).show();
	
			    $("#editTagSearch").val($("#selectedTagName").html());
			    $("#editTagSearch").focus();
			    
 			});
 			
		
		    $("#editTagSearch").on("keyup", function(e){
		    	if(yo.enter(e)){
		    		yo.NG.editTagSave();
		    	}
		    });
		    
 			$("#deleteTagBtn").on("click", function(e){
 				if($('#editDeleteTagHeader').hasClass('disabled')){return;}
 				yo.addModalDialog(yo.getModalDialogHtml({mainMsg:"Are you sure you want to delete this tag from these transactions?",
					btn1Class:"warning deleteTagBtn ofSameSize",
					btn1ADAMsg:__["Delete Tag"],
					btn1Msg:__["Delete"],
					btn1Func:"console.log(\'fix me: delete tag, reload page\')",
					btn2Class:"secondary cancelBtn ofSameSize",
					btn2ADAMsg:__["Cancel"],
					btn2Func:"yo.hideModalDialog()",
					btn2Msg:__["Cancel"]}),e.target);
 			});
       	},
       
       	renderHtmlForSearchTagMultiTxns: function(){
   			//TODO: move this to main.html and just change the header show hide logic. doesnt' have to be dynamic
   			
   			var unCheckedCheckbox = (yo.IE==8) ? '<i class="i-z0027unchecked"></i>' : params.svg.iconUnchecked;
        	
        	$("#searchResultsContainerHeaderWrapper").html('<div class="searchResultsContainerHeader">'+
        	'<div class="sideBySideColumn titleCtr" title="TRANSACTIONS">'+
            	'<span class="checkboxCtr multiSelectCheck" id="selectAllSearchTrans" tabindex="0" role="checkbox" style="display:none">'+unCheckedCheckbox+
            	'</span> TRANSACTIONS</div>'+
            	
            	'<div class="sideBySideColumn inputCtr hide">\
					<div id="search_inputTitle" class="mobileCtr inputTitle hide">\
						<a href="#" class="close" title="Close">x</a>\
						<label for="search_addTag"> Add Tag</label>\
						<a href="#" class="saveTagLink hide" >SAVE</a>\
					</div>\
					<input type="text" id="search_addTag" class="addTag" maxlength="40" title="{{__ "Type tag here"}}. {{__ "Opens recent tags dropdown"}}" placeholder="Type tag here..." data-dropdown="TagDrop"/>\
					<ul id="search_tagDropdown" class="f-dropdown" data-dropdown-content></ul>\
				</div>\
				<div class="addTagsCtr mobileCtr hide">\
					<a href="#" role="button" class="addTagButton button" aria-label="Add tags">'+__["ADD"]+' '+__["TAG"]+'</a>\
				</div>\
				<div class="editBtnCtr">\
				<a href="#" role="button" class="editTrans" aria-label="Add tag">'+__["EDIT"]+'</a>\
				</div>\
			</div>'+
        	'</div>');

     		
 			//TODO: if markup is not dynamic, I believe these bindings should go in the top / init section
 			var that = this;
 			$("#selectAllSearchTrans").on("click", function(e){
 				that.selectAllSearchTransaction();
 			});//copied from this.selectAllTransaction);
 
 			$("#selectAllSearchTrans").on("keyup", function(e){//TODO: needs to be tested
 				if(e.keyCode==13){
 					that.selectAllSearchTransaction();
 				}
 			});
 			
 			$("#search_addTag").on("click", function(){
 				
 				that.resetRecentTagsDropdown();
 				$("#search_tagDropdown li").on("click", function(e){
     				that.selectTag(e);
     			});	
 			});
 			
 			$("#search_addTag").on("tap", function(){//TODO: test
 				that.resetRecentTagsDropdown();
 				$("#search_tagDropdown li").on("tap", function(e){
     				that.selectTag(e);
     			});	
 			});
 			
 			$("#search_addTag").on("keyup", function(e){
 				if(e.keyCode==13||e.keyCode==0){ //(enter and space bar)
 					that.addTagToSelectedTrans(e);
 				}
 			});
 			
 			$(".searchSaveTag").on("click", function(e){
 				that.addTagToSelectedTrans(e);
 			});
 			
			$(".searchResultsContainerHeader .addTagsCtr .addTagButton").on("click", function(e){
				that.showMobileAddTagTextbox(e);
			});
			 
			 $(".searchResultsContainerHeader .inputTitle .close").on("click", function(){
				that.closeLightbox();
			});

			//TODO: these need to be added:
 			/*	
			"click .saveTagLink": "addTagToSelectedTrans",
			*/
			
			$(".searchResultsContainerHeader .editTrans").on("click", function(e){
				that.showMultiselectCheckbox(e);
			});
			
       	},
       	
        templateHelpers : function(){
		    var mode = this.options.mode;
		    return {
    		    listMode: function(){ return mode;}
    			,checkboxUnchecked: function(){
					return (yo.IE==8) ? '<i class="i-z0027unchecked"></i>' : params.svg.iconUnchecked;
				}
				,checkboxMinus: function(){
					return (yo.IE==8) ? '<i class="i-z0017tag"></i>' : params.svg.iconMinus;
				}
    		};    
        },
        
        onRender : function(){
        	if(!this.options.collection){
        		this.$('#'+this.mode+'_transactionlist').append('<div style="text-align:center">No Data Found</div>');
        	}
        	if( this.mode == 'past' || this.mode =='future'){ // can add show/hide logic here for timefilter
        		this.$('.timeFilter').html(new TransactionTimeFilterView({mode:this.mode}).render().el);
			}	        		
        	
            if(this.mode=="search"){
            	this.renderHtmlForSearchTagMultiTxns();
            }
            
            if(this.mode=="tag_search"){
            	this.renderHtmlForTagSearch();
            }
            
            // Enable/Disable Edit Multiple Transactions
            this.enableDisableEditMultipleTransactions();
            
        	       	
        },
        enableDisableEditMultipleTransactions: function(){
        	var editMultipleTrans = params.enableEditMultipleTransactions;
        	if(editMultipleTrans == false){
        		this.$('.checkboxCtr').hide();
        		this.$('.inputCtr').hide();
        		this.$('.buttonCtr').hide();
        		this.$('.addTagsCtr').hide();
        		this.$('.editBtnCtr').hide();
        	}
        	$(this.el).addClass('set-width-container');
        }, 		
		prepareToFetch: function(){
			var _thisView = this;
		    //TODO FIND OUT IF WE ALREADY HAVE THE RQUESTED TRANSACTIONS IN CACHE. If not
		    // set the transaction filter params here based on the _thisView.mode and call Fetch
		    var transactionFilter = {};
		    if(_thisView.mode == 'now') {
		        transactionFilter.startNumber = 0;
		        transactionFilter.endNumber = 20;
		        transactionFilter.account ='All';
		    }
		},
		
		fetchTransactions: function(filter) {
            
            var _thisView = this;
            _thisView.filter = filter;
            var transPostData=[]
            ,toDate = moment()
            ,fromDate = moment();
            
            if(filter =='1m'){
            	fromDate.subtract('months',2);
            	toDate.add('months',1);
            }else if(filter == '3m'){
            	fromDate.subtract('months',4);
            	toDate.add('months',3);
            }else if(filter == '6m'){
            	fromDate.subtract('months',6);
            	toDate.add('months',6);
            }else if(filter == '1y'){
            	fromDate.subtract('years',1);
            	toDate.add('years',1);
            }else if(filter =='2y'){
            	fromDate.subtract('years',2);
            	toDate.add('years',2);
            }
            var fromTransDate = fromDate.format('MM')+'-'+fromDate.format('DD')+'-'+fromDate.format('YYYY')
				
			, toTransDate = toDate.format('MM') + '-'+toDate.format('DD')+'-'+toDate.format('YYYY');
            
            transPostData.push('filter[]=fromdate,' + fromTransDate);
			transPostData.push('filter[]=todate,' + toTransDate);
            //TODO: Cache this by filter so we don't recall it for the same filter
            //also this is getting called for no reason on startup and slowing things down but search needs it so I've lef tit in
            /*yo.api('/services/Transaction/allJSON/', function(data){
                PARAM.transData = data;
                if (PARAM.transData) {
                    
                    if(PARAM.transData && PARAM.transData.obj.searchResult.transactions){
                        //_thisView.collection = new TransactionsCollection(PARAM.transData.obj.results? PARAM.transData.obj.results: []);   //sol1
                        //console.log(_thisView.collection);
                        _thisView.collection.reset(PARAM.transData.obj.searchResult.transactions);  // sol2
                    }
                   
                    // cache the time range transactions here
                }
                 _thisView.renderUI();  // sol1
            },transPostData.join('&'));*/
            
             
        },
		
		onClose: function() {
	      _(this.childViews).each(function(view) {
	        	view.closeView();
	        	view= null;
	      });
	   },
		
				/**timeMatches function checks to see if the time filter matches the transDate
		 * @param {Object} obj to examine
		 * @param {String} time to check against
		 * @param {String} mode to check with (posted = past, scheduled = future)
		 */
		
		timeMatches :function(obj,time,mode){
			if(time){
				var date = (obj.postDate)?obj.postDate:obj.transactionDate;//take the post date if we can get it
				if(mode=='posted'){
					if(time=='1m'){//effectively is last month
						if(moment().subtract('months',2).diff(date)<0&&moment().diff(date)>0){
							return true;
						}
					}
					if(time=='3m'){//effectively is last month
						if(moment().subtract('months',4).diff(date)<0&&moment().diff(date)>0){
							return true;
						}
					}
					if(time=='6m'){//effectively is last month
						if(moment().subtract('months',7).diff(date)<0&&moment().diff(date)>0){
							return true;
						}
					}
					if(time=='1y'){//effectively is last month
						if(moment().subtract('years',1).diff(date)<0&&moment().diff(date)>0){
							return true;
						}
					}
					if(time=='2y'){//effectively is last month
						if(moment().subtract('years',2).diff(date)<0&&moment().diff(date)>0){
							return true;
						}
					}
				}else if(mode=='scheduled'){
					if(time=='1m'){
						if(moment().add(1, 'months').diff(date)>0&&moment().diff(date)<0){
							return true;
						}
					}
					if(time=='3m'){
						if(moment().add(3, 'months').diff(date)>0&&moment().diff(date)<0){
							return true;
						}
					}
					if(time=='6m'){
						if(moment().add(6, 'months').diff(date)>0&&moment().diff(date)<0){
							return true;
						}
					}
					if(time=='1y'){
						if(moment().add(1, 'years').diff(date)>0&&moment().diff(date)<0){
							return true;
						}
					}
					if(time=='2y'){
						if(moment().add(2, 'years').diff(date)>0&&moment().diff(date)<0){
							return true;
						}
					}
				}
			}else{
				return true;//no tim provided so always return true
			}
			return false;
		},
		
		selectAllSearchTagTransaction: function(){
        	
        	var selectAllTrans = document.getElementById("selectAllTagTrans");
			this.changeCheckboxIcon(selectAllTrans);
			
			var checkboxs = $('#appendedSearchResults .multiSelectCheck')
			var status = selectAllTrans.getAttribute('checked'),i;
	
			if(status=="true"){
				$('#searchResultsContainerHeaderWrapper .saveTag').removeClass('disabled');
				//show the hidden delete tag button
	            if($('#editDeleteTagHeader')[0]){
	            	$('#editDeleteTagHeader').removeClass('disabled');
	            }
				if((yo.IE==8)){
					$(selectAllTrans).closest('.checkboxCtr').find('i').replaceWith('<i class="i-z0026checked"></i>')
				}else{
					$(selectAllTrans).closest('.checkboxCtr').find('svg').replaceWith(params.svg.iconChecked)
				}
			}else{
				//show the hidden delete tag button
	            if($('#editDeleteTagHeader')[0]){
	            	$('#editDeleteTagHeader').addClass('disabled');
	            }
				this.hideAddTagTextbox();
				$('#searchResultsContainerHeaderWrapper .saveTag').addClass('disabled');
				//hide the delete tag button
	            if($('#editDeleteTagHeader')[0]){
	            	$('#editDeleteTagHeader').addClass('disabled');
	            }
				if((yo.IE==8)){
					$(selectAllTrans).closest('.checkboxCtr').find('i').replaceWith('<i class="i-z0027unchecked"></i>')
				}else{
					$(selectAllTrans).closest('.checkboxCtr').find('svg').replaceWith(params.svg.iconUnchecked)
				}
			}
			
			for(i=1;i<checkboxs.length;i++){
				if(status=="true"){
					if(checkboxs[i].getAttribute('checked')!="true"){
						this.changeCheckboxIcon(checkboxs[i]);
					}
				}else{
					if(checkboxs[i].getAttribute('checked')=="true"){
						this.changeCheckboxIcon(checkboxs[i]);
					}
				}
			}
	    },
       	
        selectAllSearchTransaction: function(){
        	
        	var selectAllTrans = document.getElementById("selectAllSearchTrans");
			this.changeCheckboxIcon(selectAllTrans);
			
			var checkboxs = $('#searchResults .multiSelectCheck')
			var status = selectAllTrans.getAttribute('checked'),i;
	
			if(status=="true"){
				this.showAddTagTextbox();
				$('#searchResultsContainerHeaderWrapper .saveTag').removeClass('disabled');
				if((yo.IE==8)){
					$(selectAllTrans).closest('.checkboxCtr').find('i').replaceWith('<i class="i-z0026checked"></i>')
				}else{
					$(selectAllTrans).closest('.checkboxCtr').find('svg').replaceWith(params.svg.iconChecked)
				}
			}else{
				this.hideAddTagTextbox();
				$('#searchResultsContainerHeaderWrapper .saveTag').addClass('disabled');
				//hide the delete tag button
	            if($('#editDeleteTagHeader')[0]){
	            	$('#editDeleteTagHeader').addClass('disabled');
	            }
				if((yo.IE==8)){
					$(selectAllTrans).closest('.checkboxCtr').find('i').replaceWith('<i class="i-z0027unchecked"></i>')
				}else{
					$(selectAllTrans).closest('.checkboxCtr').find('svg').replaceWith(params.svg.iconUnchecked)
				}
			}
			
			for(i=1;i<checkboxs.length;i++){
				if(status=="true"){
					if(checkboxs[i].getAttribute('checked')!="true"){
						this.changeCheckboxIcon(checkboxs[i]);
					}
				}else{
					if(checkboxs[i].getAttribute('checked')=="true"){
						this.changeCheckboxIcon(checkboxs[i]);
					}
				}
			}
	    },
 
		//Edit Multiple Transactions 
		selectAllTransaction: function(e){
			var selectAllTrans = e.currentTarget
			,checkboxs = this.$('.multiSelectCheck')
			,status = selectAllTrans.getAttribute('checked'),i;
			
			if(selectAllTrans){
				for(i=0;i<checkboxs.length;i++){
					if(status=="true"){
						if(checkboxs[i].getAttribute('checked')=="true"){
							this.changeCheckboxIcon(checkboxs[i]);
						}
					}else{
						if(checkboxs[i].getAttribute('checked')!="true"){
							this.changeCheckboxIcon(checkboxs[i]);
						}
					}
				}
			}
			status = selectAllTrans.getAttribute('checked');
			if(status=="true"){
				this.showAddTagTextbox();
				$('.saveTag').removeClass('disabled').attr('tabindex','0').attr('title',__['ADD']+' '+__['TAG']+'. '+__['Enabled']);
				
			}else{
				this.hideAddTagTextbox();
				$('.saveTag').addClass('disabled').attr('tabindex','').attr('title',__['ADD']+' '+__['TAG']+'. '+__['Disabled. To enable, select transactions, input tag names or select recent tag suggestions from dropdown']);;
				//hide the delete tag button
	            if($('#editDeleteTagHeader')[0]){
	            	$('#editDeleteTagHeader').addClass('disabled');
	            }
			}
		},
		selectGroupedTransactions: function(e){
			this.changeCheckboxIcon(e.currentTarget);
			var groupCheckbox = e.currentTarget
			,checkboxsMode =  $(groupCheckbox).attr('id')	
			,status = groupCheckbox.getAttribute('checked')	
			,subHeadCheckBox = this.$(".subHead .multiSelectCheck")
			,checkboxs,i;
			if(checkboxsMode && checkboxsMode.indexOf("cleared") >= 0){
				checkboxs = this.$(".multiSelectCheck[tGroup='cleared']");
			}else if(checkboxsMode && checkboxsMode.indexOf("pending") >= 0){
				checkboxs = this.$(".multiSelectCheck[tGroup='pending']");
			}else if(checkboxsMode && checkboxsMode.indexOf("scheduled") >= 0){
				checkboxs = this.$(".multiSelectCheck[tGroup='scheduled']");				
			}
			for(i=0;i<checkboxs.length;i++){
				if(status=="true"){
					if(checkboxs[i].getAttribute('checked')!="true"){
						this.changeCheckboxIcon(checkboxs[i]);
					}
				}else{
					if(checkboxs[i].getAttribute('checked')=="true"){
						this.changeCheckboxIcon(checkboxs[i]);
					}
				}
			}
			this.showHideAddTagTextbox(e);
			//this.closeAllAccordion(e);
			this.checkSelectAllStatus(e);
		},
		selectDateGroupedTransactions: function(e){
			this.changeCheckboxIcon(e.currentTarget);
			var dateGroupCheckbox = e.currentTarget
			,checkboxDate = $(dateGroupCheckbox).attr('tDate')
			,status = dateGroupCheckbox.getAttribute('checked')
			,subHeadCheckBox = this.$(".subHead .multiSelectCheck")
			,groupCheckbox = $(dateGroupCheckbox).closest('.sub-title-light').prevAll('.sub-title-dark').first().find('.groupByStatus')
			,checkboxs = this.$('.multiSelectCheck[tDate='+checkboxDate+']')
			,i;
			
			for(i=0;i<checkboxs.length;i++){
				if(status=="true"){
					if(checkboxs[i].getAttribute('checked')!="true"){
						this.changeCheckboxIcon(checkboxs[i]);
					}
				}else{
					if(checkboxs[i].getAttribute('checked')=="true"){
						this.changeCheckboxIcon(checkboxs[i]);
					}
				}			
			}
			if(groupCheckbox && groupCheckbox.attr("checked")=="true"){
				groupCheckbox.setAttribute("checked","true");
			}
			this.showHideAddTagTextbox(e);
			//this.closeAllAccordion(e);
			this.checkSelectAllStatus(e);
		},
		unselectGroup:function(e){
			var checkbox = e.currentTarget
			,dateGroupCheckbox = $(checkbox).parents('div.accordion-navigation').prevAll('.sub-title-light').first().find('.groupByDate')
			,modeGroupCheckbox = $(checkbox).parents('div.accordion-navigation').prevAll('.sub-title-dark').first().find('.groupByStatus')
			,subHeadCheckBox = this.$(".subHead .multiSelectCheck");
			if(dateGroupCheckbox && dateGroupCheckbox.attr("checked")=="true"){
				dateGroupCheckbox.attr("checked","false");
			}
			if(modeGroupCheckbox && modeGroupCheckbox.attr("checked")=="true"){
				modeGroupCheckbox.attr("checked","false");
			}
		},
		showHideAddTagTextbox: function(e){
			var checkboxs = this.$('.multiSelectCheck'),i;
			for(i=0;i<checkboxs.length;i++){
				if(checkboxs[i].getAttribute('checked')=="true"){
					this.showAddTagTextbox();
					break;
				}else{
					this.hideAddTagTextbox();
				}
			}				
		},
		showAddTagTextbox: function(){
			var addTagInput = this.$("#"+this.mode+"_addTag");
			var arrowIcon = this.$(".accordion .right span.chevron");
			if($('#editDeleteTagHeader')[0]){
            	$('#editDeleteTagHeader').removeClass('disabled');
            }
			var mobileView = yo.width <= 600;
			if(addTagInput && addTagInput.hasClass('hide') && !mobileView){
				addTagInput.removeClass('hide');
				$('.inputCtr').removeClass('hide');
			}
			if(arrowIcon){
				$(arrowIcon).hide();
			}
			//Show Add tag button on mobile
			if(mobileView){
				this.showAddTagsButton();
			}
		},
		hideAddTagTextbox: function(){
			var addTagInput = this.$("#"+this.mode+"_addTag");
			var arrowIcon = this.$(".accordion .right span.chevron");
			//show the hidden delete tag button
            if($('#editDeleteTagHeader')[0]){
            	$('#editDeleteTagHeader').addClass('disabled');
            }
			var mobileView = yo.width <= 600;
			if(addTagInput && !addTagInput.hasClass('hide')){
				addTagInput.addClass('hide');
				$('.inputCtr').addClass('hide');
			}
			if(arrowIcon){
				$(arrowIcon).show();
			}
			//Show Add tag button on mobile
			if(mobileView){
				this.hideAddTagsButton();
			}
		},
		closeAllAccordion: function(e){
			this.children.call("closeOpenedAccordion", e);
		},
		changeCheckboxIcon: function(checkbox){
			//var headerCheckboxCtr = this.$('.subHead .titleCtr .checkboxCtr');
			if(checkbox.getAttribute('checked')=="true"){//toggle it manually since they are no longer input boxes for ADA reasons
				checkbox.setAttribute('checked','false');
			}else{
				checkbox.setAttribute('checked','true');
			}
			if(checkbox &&checkbox.getAttribute('checked')=="true"){
				if((yo.IE==8)){
					$(checkbox).find('i').replaceWith('<i class="i-z0026checked"></i>');
				}else{
					$(checkbox).find('svg').replaceWith(params.svg.iconChecked);
				}
			}else{
				if((yo.IE==8)){
					$(checkbox).find('i').replaceWith('<i class="i-z0027unchecked"></i>');
				}else{
					$(checkbox).find('svg').replaceWith(params.svg.iconUnchecked);
				}
			}
		},
		checkSelectAllStatus: function(e){	
			var allCheckbox = this.$(".accordion-navigation .multiSelectCheck")
			,allCheckboxStatus
			,checkboxCount = allCheckbox.length		
			,checkedCount = 0
			,unCheckedCount = 0
			,i;				
			for( i=0;i<checkboxCount;i++){
				if(allCheckbox[i].getAttribute('checked')=="true"){	
					checkedCount = checkedCount + 1;
				}else{
					unCheckedCount = unCheckedCount + 1;
				}
			}
			this.changeSelectAllStatus(checkboxCount, checkedCount, unCheckedCount)
		},
		/**changes Select All checkbox to correct icon and status
		 * @param {Number} checkboxCount is number of checkboxes total
		 * @param {Number} checkedCount is number of checked Checkboxes
		 * @param {Number} unCheckedCount is number of unchecked Checkboxes 
		 */
		changeSelectAllStatus: function(checkboxCount, checkedCount, unCheckedCount){
			var headerCheckboxCtr;
			if($('#searchResultsSecondary')[0]&&$('#searchResultsSecondary')[0].style.display=="block"){
				headerCheckboxCtr=$('#searchResultsSecondary').find('.searchResultsContainerHeader').find('.titleCtr')
			}else{
				headerCheckboxCtr=this.$('.subHead .titleCtr .checkboxCtr');
			}
			if(this.mode=="search"&&$('#searchResultsPrimary')[0].style.display!='none'){ headerCheckboxCtr = $("#selectAllSearchTrans");}
			
			var headerCheckbox = $(headerCheckboxCtr).find('.multiSelectCheck');
			if(checkedCount == checkboxCount){ // all trans are selected
				if((yo.IE==8)){					
					$(headerCheckboxCtr).find('i').replaceWith('<i class="i-z0026checked"></i>')
				}else{
					$(headerCheckboxCtr).find('svg').replaceWith(params.svg.iconChecked)
				}
			}else if(unCheckedCount == checkboxCount){ // all trans are un selected
				headerCheckbox.prop("checked", false).trigger('change');
				if((yo.IE==8)){					
					$(headerCheckboxCtr).find('i').replaceWith('<i class="i-z0027unchecked"></i>')
				}else{
					$(headerCheckboxCtr).find('svg').replaceWith(params.svg.iconUnchecked)
				}
			}else if(checkedCount > 0 ){ // few trans are selected
				headerCheckbox.prop("checked", true).trigger('change');
				if((yo.IE==8)){					
					$(headerCheckboxCtr).find('i').replaceWith('<i class="i-z0028minus"></i>')
				}else{
					$(headerCheckboxCtr).find('svg').replaceWith(params.svg.iconMinus)
				}

			}	
		},
		addTagToSelectedTrans: function(e) {
			this.showTagAutoComplete(e.target); 
			this.addTagInput = $("#"+this.mode+"_addTag");  
		    var tagValue = this.addTagInput.val();
		   	// if no value entered
		    if (!$.trim(tagValue)) {
		    	this.resetRecentTagsDropdown();
		    	
		    	if(this.mode=="search"){
		    		$('.saveSearchTag').addClass('disabled');
		    		//hide the delete tag button
		            if($('#editDeleteTagHeader')[0]){
		            	$('#editDeleteTagHeader').addClass('disabled');
		            }
		    	}else{    
			    	if( this.$("#subHead").find('.saveTag')) { 
			    		this.$("#subHead").find('.saveTag').addClass('disabled'); 
			    		//hide the delete tag button
			            if($('#editDeleteTagHeader')[0]){
			            	$('#editDeleteTagHeader').addClass('disabled');
			            }
			    	} 
		    	}
		    	return;
		    }
            if (!yo.enter(e) && e.type!='click') { 
            	y = tagValue[tagValue.length-1];
            	if(this.isBadChar(y)) {
            		var newVal = tagValue.replace(/[^\w\s]/gi, '');
            		this.addTagInput.val(newVal);
            	}
            	if(this.mode=="search"){
            		$('.saveSearchTag').removeClass('disabled');
            	}else{
            		// remove the disabled class from save button
            		if( this.$("#subHead").find('.saveTag') && this.$("#subHead").find('.saveTag').hasClass('disabled')) { this.$("#subHead").find('.saveTag').removeClass('disabled'); }
               	}
                this.showTagAutoComplete(e.target);
                 
                return;
            }
             // reset add tag autocomplete dropdown
            this.resetRecentTagsDropdown();
            $(document).foundation('dropdown', 'closeall'); // closes the tag autocomplete dropdown
            this.children.call("addTagToMultipleTrans", tagValue); 
            
            //clear tag text field
            this.addTagInput.val('');
		    
		    // Show success message.
			var successMsg = this.$('.topMsgCtr');
		    if(successMsg[0]){
		    	if(yo.width <= 768){
		    		$(successMsg).find('p').html('Tag added successfully.');
		    	}
		    	var msgNode = successMsg[0].cloneNode(true);
		    	msgNode.className = msgNode.className.replace('hide','');
		    	if(yo.msgNode){
		    		document.body.removeChild(yo.msgNode);
		    		delete yo.msgNode;
			    }
		    	yo.msgNode = msgNode;
		    	document.body.appendChild(msgNode);
		    	
		    }
			//Remove the message after 8sec
		    setTimeout(function() {
			    if(yo.msgNode){
		    		document.body.removeChild(yo.msgNode);
		    		delete yo.msgNode;
			    }
			}, 10000);

			//Remove Mobile overlay and textbox
			if(yo.width < 768){
				var overlay = $('.black_overlay');
				var tagTextbox = $('.addTag');
				var inputTitle = $('.inputTitle');
				var inputCtrl = $('.inputCtr');
				$(overlay).hide();
				$(tagTextbox).addClass('hide');
				$(inputTitle).addClass('hide');
				$(inputCtrl).addClass('hide');
			}

		},
		closeSuccessMsg: function(){
		    if(yo.msgNode){
		    	//successMsg.addClass('hide');
		    	document.body.removeChild(yo.msgNode);
		    	delete yo.msgNode;
		    }
		},
		isBadChar : function(y){			
			var badCharsFilter = "@#$%^~&*=;,\\\"{}<>[]",i;
			for(i=0;i<badCharsFilter.length;i++){
				if(y == badCharsFilter[i]){
					return true;
				}
			}
			return false;
		},		
		setSuggestedTags: function(matches){
			this.suggestedTags = [];
			var i;
			// get tags from allTags starting with given keyword			
			if(matches.length>0){				
				for(i=0; i<matches.length; i++){
					this.suggestedTags.push(matches[i]);
				}
			}
		},
		showTagAutoComplete:function(el){	
			//run query for autocomplete matches			
			this.setSuggestedTags(TransactionCache.allTags);
            if(this.suggestedTags && this.suggestedTags.length>0){
				var lis = '',i;
				for(i=0; i<this.suggestedTags.length; i++){			
					if(this.suggestedTags[i].toLowerCase().indexOf($(el).val().toLowerCase()) == 0) {
						var liEl = '<li><a href="#">'+this.suggestedTags[i]+'</a></li>';
						lis += liEl;
					}
				}		
				$("#tagDropdown").html(lis);
				var d= $("#tagDropdown");
				if(lis !=''){
					Foundation.libs.dropdown.open(d,this.$("#"+this.mode+"_addTag"));
				}
				else{
					Foundation.libs.dropdown.close(d);
				}	
			}
		},	
		resetRecentTagsDropdown : function() {
				var content = [];
				this.addTagInput = this.$("#"+this.mode+"_addTag");
			  	var tagValue = this.addTagInput.val();
		    	if ($.trim(tagValue)) { 
		    		$("#"+this.mode+"_tagDropdown").html(content.join(''));
		    		return;
		    	}	
				this.setSuggestedTags(TransactionCache.recentTags);
				content.push(yo.getDropdownOptions(this.suggestedTags));
				$("#"+this.mode+"_tagDropdown").html(content.join(''));
				Foundation.libs.dropdown.open($("#"+this.mode+"_tagDropdown"),$("#"+this.mode+"_addTag"));			
				
		},
		selectTag: function(e){
			var name = $(e.target).html();
	        this.addTagInput = $("#"+this.mode+"_addTag");
	        this.addTagInput.val(name);
	        $(document).foundation('dropdown', 'closeall');
	        
	        // remove the disabled class from tag button
            if($(".sub-title").find('.saveTag') && $(".sub-title").find('.saveTag').hasClass('disabled')) { 
            	$(".sub-title").find('.saveTag').removeClass('disabled'); 
            }
            //show the hidden delete tag button
            if($('#editDeleteTagHeader')[0]){
            	$('#editDeleteTagHeader').removeClass('disabled');
            }
            if(this.mode=="search"){
            	$('#searchResultsContainerHeaderWrapper .saveTag').removeClass('disabled');
            }                 
		},
		showMultiselectCheckbox: function(e){
			var editButton = e.target;
			var checkboxCtr = this.$('.checkboxCtr');
			var accordion = this.$('div.accordion-navigation');
			
			if(this.mode=="search"){
				checkboxCtr = $("#searchResultsContainer .checkboxCtr");
				accordion = $("#searchResultsContainer div.accordion-navigation");
			}
			
			if(this.mode=="tag_search"){
				checkboxCtr = $("#appendedSearchResultsContainer .checkboxCtr");
				accordion = $("#appendedSearchResultsContainer div.accordion-navigation");
			}
			
			if(editButton && $(editButton).hasClass('cancel')){
				
				$(editButton).removeClass('cancel')
				$(checkboxCtr).hide();
				if(this.mode=="search"||this.mode=="tag_search"){
					$($(editButton.parentNode.parentNode.parentNode.parentNode).find('.module_'+params.transModule)[0].firstChild).removeClass('multipleTransEnabled');
				}else{
					$($(editButton).parents('.module_'+params.transModule)[0].firstChild).removeClass('multipleTransEnabled');
				}
				$(editButton).html('EDIT');
				$(accordion).removeClass('editMultipleTrans');
				this.changeCheckboxStatus();
				this.hideAddTagsButton();
				if($('#editDeleteTagHeader')[0]){
					if(!$('#editDeleteTagHeader').hasClass('disabled')){
						yo.wasEnabled = true;
						$('#editDeleteTagHeader').addClass('disabled');
					}
	            	
	            }
	            
				return;
			}
			if(checkboxCtr){
				if(this.mode=="search" && yo.width <= 600){
					$(checkboxCtr).attr('style','display:inline');
				}else{
					$(checkboxCtr).attr('style','display:inline-block');
				}
				if(this.mode=="search"||this.mode=="tag_search"){
					$($(editButton.parentNode.parentNode.parentNode.parentNode).find('.module_'+params.transModule)[0].firstChild).addClass('multipleTransEnabled');
				}else{
					$($(editButton).parents('.module_'+params.transModule)[0].firstChild).addClass('multipleTransEnabled');
				}
				if(yo.wasEnabled){
					yo.wasEnabled=false;
					$('#editDeleteTagHeader').removeClass('disabled');
				}
				$(editButton).addClass('cancel');
				$(accordion).addClass('editMultipleTrans');
				$(editButton).html('CANCEL');

			}
			
		},
		showAddTagsButton: function(e){
			var addTagsButton = this.$('.addTagsCtr');
			
			if(this.mode=="search"){
				addTagsButton = $(".searchResultsContainerHeader .addTagsCtr");
			}
			$(addTagsButton).css('top', window.innerHeight - 50)
			if(addTagsButton){
				$(addTagsButton).removeClass('hide');
			}
		},
		hideAddTagsButton: function(e){
			var addTagsButton = this.$('.addTagsCtr');
			if(this.mode=="search"){
				addTagsButton = $(".searchResultsContainerHeader .addTagsCtr");
			}
			if(addTagsButton){
				$(addTagsButton).addClass('hide');
			}
		},
		showMobileAddTagTextbox: function(e){
			var addTagInput = $('#'+this.mode+'_addTag');
			var overlay = $('#'+this.mode+'_black_overlay');
			var inputTitle = $('#'+this.mode+'_inputTitle');
				$(addTagInput).removeClass('hide');
				$(inputTitle).removeClass('hide');
				
				if(this.mode=="search"){
					$('.searchResultsContainerHeader .inputCtr').removeClass('hide');
				}else{
					$('.inputCtr').removeClass('hide');
				}
				
				$(overlay).show();
				$(addTagInput).focus();
		},
		closeLightbox: function(e){
			var addTagInput = $('#'+this.mode+'_addTag')
			,overlay = $('#'+this.mode+'_black_overlay')
			,inputTitle = $('.inputTitle');
				$(addTagInput).addClass('hide');
				$(inputTitle).addClass('hide');
				$('.inputCtr').addClass('hide');
				if(this.mode=="search"){
					$('.searchResultsContainerHeader .inputCtr').addClass('hide');
				}
				$(overlay).hide();
		},
		changeCheckboxStatus: function(e){
			var checkboxs = this.$(".multiSelectCheck"),i;
			for(i=0;i<checkboxs.length;i++){
				$(checkboxs[i]).prop("checked", false).trigger('change');
			}	

		}			
 	});
 	
	return TransactionListView;
	
});

/**
 * implementing Collection module using service api
 * Putting data from api into PARAM.transData
 * @param {Backbone} loading Backbone modules
 * @param {TransactionsModel} getting Transactions model module
 */

define('10003507_js/collection/TransactionsCollection',['10003507_js/models/TransactionsModel'], function(TransactionsModel) {
    
	TransactionsCollection = Backbone.Collection.extend({
	
		initialize: function(){
			
			//console.log('DEBUG- Transactions Collection initialization');
		},
		model: TransactionsModel,
		
		parse: function(response) {
		    //console.log(response);
		    //sort by date descending
            return response.searchResult.transactions;
        },
         
         byStatus: function(status) {
            
            if( status === 'pending' || status === 'scheduled' || status === 'cleared'){
               return this.filterBy(status); 
            }
            else if( status == 'all') {
                var list1 = this.filterBy('scheduled'); 
                var list2 = this.filterBy('pending'); 
                var list3 = this.filterBy('cleared'); // TODO: basically everything else other than 1st two
                list1.add(list2.models, {silent : true});
                list1.add(list3.models, {silent : true});
                list2=null;
                list3=null;
                return list1;
            }
         },
         
         filterBy : function(status) {
            var pDate= '', pStatus=''; 
                
            filtered = this.filter(function(txn) {
              if( txn.get("status").description === status ){  
                  if( txn.get('transactionDate') != pDate){
                      txn.set({'showDateHeader': true}, {silent : true}); 
                      pDate = txn.get('transactionDate');
                  } 
                  if( txn.get("status").description != pStatus){
                      txn.set({'showStatusHeader': true}, {silent : true}); 
                      pStatus = txn.get("status").description;
                  }            
                  return true;
              } 
            });
            
            return( new TransactionsCollection(filtered));
         }

	});
	return TransactionsCollection;
});
		
	
/**
 * Responsible for rendering the Transactions list 
 * Including list for Past, Now, Future and search results
 * Call to yo.when to timeout till backbone loads
 * yo.when is in base.js 
 * @param {Backbone} loading backbone modules
 * @param {TransactionsCollection} loading the Collections module of Transactions
 * init like so: 
 * var listView = new TransactionsListView({_thisView.mode:"now", _thisView.divId:"some_thisView.divId", keyword:"somekeyword"});
 * passed in args can be accessed in this.options
 */

 define('10003507_js/views/TransactionSearchView',[ '10003507_js/compiled/finappCompiled','10003507_js/views/TransactionListView','10003507_js/collection/TransactionsCollection','10003507_js/models/TransactionCache'], 
    function(templates, TransactionListView,TransactionsCollection , TransactionCache ) {
     
    
 	var TransactionSearchView = Backbone.Marionette.ItemView.extend({

        initialize : function(options) {
            this.moduleKey = options.moduleKey;
        },

        template: templates['transactionSearch'],
        
        
        events: {
            'keypress #searchBox': 'searchTxns'
        },
        
 		tagName: 'div',
 		
 		searchTxns: function(){
 		    var self=this;
 		    var transView = null;
 		    var transCollection = new TransactionsCollection();
            
            transCollection.fetch({reset: true,
                url: Application.Wrapper.getAPIUrl('searchTransactions'),
                
                // url : Wrapper.getAPIUrl('InternalPassThrough'),
                //data : fileter[]=Wrapper.getAPIUrl('popularSites')&filter[]=get&filete,
                success: function(collections, response) {
                    
                         transView = new TransactionListView({ collection: self.transCollection, moduleKey : self.moduleKey });

                        $('#transactionResults').html(transView.render().el);
                   
                        yo.uiLoad.end();
                },
                error: function (xhr, status, errorThrown) {
                    console.log('Error in fetching transactions.'+status);
                }
            });
 		}
 	});	 	
	return TransactionSearchView;
	
});

/**
 * Responsible for rendering the Transactions list 
 * Including list for Past, Now, Future and search results
 * Call to yo.when to timeout till backbone loads
 * yo.when is in base.js 
 * @param {Backbone} loading backbone modules
 * @param {TransactionsCollection} loading the Collections module of Transactions
 * init like so: 
 * var listView = new TransactionsListView({mode:"now", divId:"someDivId", keyword:"somekeyword"});
 * passed in args can be accessed in this.options
 * 
 * /Users/rpawar/Perforce/rpawar_rws-macpro/razor/appsplatform/platformplus/nodeserver/vnode//services/data/stubs/post_v10jsonsdkTransactionTagManagementgetUserTransactionTags.json' 
 */

 	
define('10003507_js/views/TransactionTagListView',['10003507_js/models/TransactionCache'], function(TransactionCache) {
 	TransactionTagListView = Backbone.Marionette.ItemView.extend({
 		
 		initialize: function(){
 			
 		    var _thisView = this;
			this.divId = "tagsSearchResults";
			this.tagType = 'all';
			this.keyword = '';
			this.allTags = TransactionCache['allTags'] || [];
			this.recentTags = TransactionCache['recentTags'] || [];
			this.isSearchView = this.options.isSearchView;
		},
		
		/**
		 * tagType : string : recent or all
		 */	
		renderView: function(){
			// if tag feature is OFF return immediately 
			if(!yo.truth(params.switchEnableTags)) { return;}
			
			var _thisView = this;
			// show loading icon in the given div
            if( $("#"+_thisView.divId) ) {
            	$("#"+_thisView.divId).html('<span>Loading...</span>');
            }  
            	
            yo.uiLoad.start();
            
            if( _thisView.allTags.length == 0) {
            	this.fetchTransactionTags(true);	
            }
            else {
            	this.renderUI();
            }
            
         },
         
         renderUI: function(tagType){   
             
            var _thisView = this;	
            
            $("#tagsSearchResultsContainerHeaderWrapper").html('<div class="searchResultsContainerHeader">TAGS</div>');
            
            // remove the loading icon
            yo.uiLoad.end();
            
            if(tagType) this.tagType = tagType;
            
            // show recent tags 
            if(this.tagType == 'recent')   {
            	          
				this.$el.html( this.getViewTemplate(_thisView.recentTags));
			}	
			else {
				// get tags from allTags starting with given keyword
				var matchingTags =[];
				for(i=0;_thisView.allTags && i<_thisView.allTags.length ; i++)	{
					if( _thisView.allTags[i].indexOf(_thisView.keyword) == 0 )
						matchingTags.push( _thisView.allTags[i]);
				}			
				
			 	this.$el.html( this.getViewTemplate(matchingTags));
			} 	
		 	if( $("#"+_thisView.divId) ) {
		 		$("#"+_thisView.divId).html(this.el.innerHTML);
		 	}
			
		},
		
		renderRecentTags: function(){   
             
            var _thisView = this;
            this.tagType = 'recent';
			this.renderView();
		
		},

        renderMatchingTags: function(keyword, isSearchView){   
             
            var _thisView = this;	
           	this.tagType = 'all';
           	this.keyword = keyword;
           	this.isSearchView = isSearchView;
			this.renderView();
		
		},

		
		getRecentTransactionTags: function(){
			 TransactionCache.recentTags && TransactionCache.recentTags.length > 0 ?  TransactionCache.recentTags : this.fetchTransactionTags();
			 return TransactionCache.recentTags;
		},
		getAllTransactionTags: function(){
			TransactionCache.allTags && TransactionCache.allTags.length > 0 ?  TransactionCache.allTags : this.fetchTransactionTags();
			return TransactionCache.allTags;
		},
		
		// force refresh cache
		refreshTagCache : function() {
			
			this.fetchTransactionTags();
		},
		
		fetchTransactionTags: function(render) {
            
            var _thisView = this;
            //TODO: change the API call to getALL Tags
            
            var userTransactionTagsAPI = 'filter[]=requestType,POST&filter[]=url,/v1.0/jsonsdk/TransactionTagManagement/getUserTransactionTags&jsonFilter={"maxRecentTags":""}';
			yo.api('/services/InternalPassThrough/makeCall/', function(data) {
				
                    PARAM.tagsData = data;
                    if (PARAM.tagsData && PARAM.tagsData.obj){
                            
                        _thisView.recentTags = PARAM.tagsData.obj.recentTags;
                        _thisView.allTags = PARAM.tagsData.obj.allTags;
                        
                        TransactionCache.recentTags = PARAM.tagsData.obj.recentTags;
                        TransactionCache.allTags = PARAM.tagsData.obj.allTags;
                        
                        
                       	if( render) {
                       		_thisView.renderUI();  	
                       	}
                        
                        
                    }else{
                        $('.empty').removeClass('hide');
                        document.getElementById('load').className="hide load";
                        $('body').removeClass('loading');
                        yo.accountType = "e";//just needs to not be empty
                    }
                }, userTransactionTagsAPI );
        },

		
		/***
		 * HTML Template for Transactions Module
		 * @param {results} data is the json data for transactions
		 * @param {mode} if the transaction is posted,pending or scheduled
		 * @param {boolean} noMenu if we don't want a filter menu
		 */
		
		getViewTemplate : function( tagList){
			var _thisView = this;
			var content = [];
			
			
			if( !tagList || tagList.length == 0) {
				if(_thisView.isSearchView){
					$("#tagsSearchResultsContainerHeaderWrapper").html("");
					return;
				}else{
					content.push('<b>No Tags Found</b>');
					return content.join('');
				}
			}
			
			/*
			 * extracting tags data from ...
			 */
			content.push('<div class="accordion tags"><div class="accordion-navigation">');
			var className = "tagListItem";
			for (var i=0; tagList && i<tagList.length;i++) {
				if(i+1 == tagList.length){
					className += " last";
				}
				content.push('<div class="'+className+'" title="'+tagList[i]+'" onclick="yo.NG.doTagSearch(\''+tagList[i]+'\')">'+tagList[i]+'</div>');
			}	
			content.push('</div></div>');
							
			return content.join('');
		}
		
			
 	});
 	
	return TransactionTagListView;
	
});
define('10003507_js/controller/TransactionController',['10003507_js/views/TransactionSearchView','10003507_js/views/TransactionListView','10003507_js/views/TransactionTagListView','10003507_js/collection/TransactionsCollection','10003507_js/models/TransactionCache'], 
	function(TransactionSearchView,TransactionListView, TransactionTagListView, TransactionsCollection, TransactionCache ) {
		transactionController = Backbone.Marionette.Controller.extend({
        initialize: function() {
            //console.log('TransactionController Controller is initialized.');
            //set the default txn filter in the contructor
        },
        
        

        start: function(options) {
            var self = this;

            // doing prep work to set transaction cache with allTags and recentTags
            TransactionCache.refreshTags();

			
			this.region = options.region;
			//TODO need to rename mode to filter in app core
			if(options.mode){
				// only override the values that are passed in filter
				this.txnFilter = options.mode;
			}
			else {
				this.txnFilter = new yo.TransactionFilter();
			}
             			
            
            var mode = this.txnFilter.get('mode');
            //(typeof self.options.mode != 'undefined' ) ?  self.options.mode : 'now';
            var status = 'all';
            if(mode == 'past') {
                status = 'cleared';
                mode ='past';
            }      
            else if( mode == 'future') {
                status = 'scheduled';
                mode = 'future';
            }
            else if( mode == 'search') {
            	this.txnFilter.set({keyword: $("#searchInput").val()});
            }    
            var postData = this.getTransactionFilterData();
            if( !PARAM.transData || !PARAM.transData.obj || !PARAM.transData.obj.results ) {
				yo.api('/services/Transaction/allJSON/', function(data){
					PARAM.transData = data;
					if( PARAM.transData && PARAM.transData.obj && PARAM.transData.obj.searchResult&&PARAM.transData.obj.searchResult.transactions&&PARAM.transData.obj.searchResult.transactions.length) {
		    		  self.collection = new TransactionsCollection(PARAM.transData.obj.searchResult.transactions? PARAM.transData.obj.searchResult.transactions: [] );
		    		}else{
		    			//no data condition
		    			var noData=true;
		    			var noDataStr = '<div class="sub-title">'+__["Transactions"]+'</div><div class="sub-title nodata">'+__["There is no data available"]+'</div>';
		    		}
		    		if( self.collection ){
		    			var transView = new TransactionListView({ collection: self.collection.byStatus(status), moduleKey : self.options.moduleKey, mode:mode, accountId : self.txnFilter.get('acctGroupId')});
		    		}	
		    		else {
		    			var transView = new TransactionListView({ collection: self.collection, moduleKey : self.options.moduleKey, mode:mode });
		    		}
		    		//does region exist? else create one
		    		// region.show has a lot of adv wrt performance & memeory management. 
		    		// The moment you rerender a view in the same region, all previos views,childviews and events associated with that region are destroyed 
		    		
		    		if(options.region.$el){
		    			if(noData){
		    				options.region.$el.html(noDataStr);
		    				return;
		    			}
                        options.region.show(transView);
                    }    
                    else {
                    	var region = new Backbone.Marionette.Region({
									  el: $(options.region)
								 	});
						if(noData){
		    				$(options.region).html(noDataStr);
		    				return;
		    			}
                        region.show(transView);
                        $(options.region).addClass('module_10003507'); // TODO:quick & dirty fix for timebeing. Need to fix the loadModule call from Timely
                    }
                    $(document).foundation({
						accordion: {
							active_class:'active',
							multi_expand: true,
							toggleable: true
						}
					});
				}, postData);
					
			}
                
            /*old code, doens't work in mobile
             * 
             * 
             *this.transCollection.fetch({reset: true,
                url: Application.Wrapper.getAPIUrl('searchTransactions'),
                
                success: function(collections, response) {
                    //console.log("trans===",collections);
                    //console.log("trans filtered===",  self.transCollection.byStatus('all'));
                    var transView = new TransactionListView({ collection: self.transCollection.byStatus(status), moduleKey : self.options.moduleKey, mode:self.options.mode });
                    //options.region.show(transView);
                    
                    if(options.region.$el){
                        options.region.$el.html(transView.render().el);
                    }    
                    else {
                        $(options.region).html(transView.render().el);
                    }
                    $(document).foundation({
						accordion: {
							active_class:'active',
							multi_expand: true,
							toggleable: true
						}
					});
                },
                error: function (xhr, status, errorThrown) {
                    console.log('Error in fetching transactions.'+status);
                }
            });*/
           
           if( mode == 'search' || mode == 'tag_search') {
           		//only search tags if have a value in the search box
           		if(mode== 'search' && this.txnFilter.get('keyword')!="" && this.txnFilter.get('keyword').length>1){
	           		var transactionTagList = new TransactionTagListView();
	           		transactionTagList.renderMatchingTags($("#searchInput").val(),true);
           		}
           }
            
        },
        
        showresults: function(){
            console.log('showing search results');
        },
        
        getTransactionFilterData : function(){
        	var postData =[];
        	postData.push('filter[]:group_id,' + this.txnFilter.get('acctGroupId'));
			postData.push('filter[]:category_id,' + this.txnFilter.get('categoryId'));
			postData.push('filter[]:Custom Dates');
			postData.push('filter[]:statementdaterange,null');
			postData.push('filter[]:description');
			postData.push('filter[]:pagefastforwardreverse,false');
			postData.push('filter[]:blk,1');
			postData.push('filter[]:blkSize,25');
			postData.push('filter[]:backwardfetchusertrans,false');
			postData.push('filter[]:container,all');
			postData.push('filter[]:callFromAccSummary,undefined');
			postData.push('filter[]:callFromBudget,undefined');
			postData.push('filter[]:callFromEmbeddedPage,undefined');
			postData.push('filter[]:page_emb_param,undefined');
			postData.push('filter[]:account_id_emb_param,undefined');
			postData.push('filter[]:container_emb_param,undefined');
			postData.push('filter[]:groupId_emb_param,undefined');
			postData.push('filter[]:categoryId_emb_param,undefined');
			postData.push('filter[]:searchfieldvalue,' + this.txnFilter.get('keyword'));
			postData.push('filter[]:advbusinessvalue,false');
			postData.push('filter[]:advtax_deductablevalue,false');
			postData.push('filter[]:advmedicalvalue,false');
			postData.push('filter[]:advreimbursablevalue,false');
			postData.push('filter[]:fromamountvalue,' + this.txnFilter.get('fromAmount'));
			postData.push('filter[]:toamountvalue,' + this.txnFilter.get('toAmount'));
			postData.push('filter[]:fromcalendervalue,' + this.txnFilter.get('fromDate'));
			postData.push('filter[]:tocalendervalue,' + this.txnFilter.get('toDate'));
			return postData.join('&');
        }
        
        
	});
	return transactionController;
});

/*
 https://finapp.moneycenter.yodlee.com/services/Transaction/all/?app=10003407&instance=11622833&status=published&token=1e34fce46a3af95fa3f176724877b75c43330b3d03f70aba725c82898f903441&resturl=https://rest.yodlee.com/services/srest/moneycenter&version=7.7
 * 
 * production sample filter
 * 
filter[]:save_pref,Filter.category_id
filter[]:group_id,-3
filter[]:category_id,102
filter[]:Custom Dates
filter[]:statementdaterange,null
filter[]:statementdaterange,null
filter[]:description
filter[]:pagefastforwardreverse,false
filter[]:blk,1
filter[]:blkSize,25
filter[]:backwardfetchusertrans,false
filter[]:container,all
filter[]:callFromAccSummary,undefined
filter[]:callFromBudget,undefined
filter[]:callFromEmbeddedPage,undefined
filter[]:page_emb_param,undefined
filter[]:account_id_emb_param,undefined
filter[]:container_emb_param,undefined
filter[]:groupId_emb_param,undefined
filter[]:categoryId_emb_param,undefined
filter[]:searchfieldvalue,
filter[]:advbusinessvalue,false
filter[]:advtax_deductablevalue,false
filter[]:advmedicalvalue,false
filter[]:advreimbursablevalue,false
filter[]:fromamountvalue,100
filter[]:toamountvalue,200
filter[]:fromcalendervalue,1416297600000
filter[]:tocalendervalue,1416470400000
 * 
 * 
 * 
 * */;
define('10003507_js/finapp',['10003507_js/controller/TransactionController'], function(TransactionController) {
	var module = Application.Appcore.Module.extend({
		controller : TransactionController,


		routes : {
			///"loginForm" : "getLoginForm",
		},

		events : {
			//"ADD_PAYEE" : "showMessage"
		},	

        initialize : function(options) {
            this.region = this.getRegion();
        },
        
        getRegion :function(){
            return "#nowInprogressTransactions";
        },
	});
	return module;
});

