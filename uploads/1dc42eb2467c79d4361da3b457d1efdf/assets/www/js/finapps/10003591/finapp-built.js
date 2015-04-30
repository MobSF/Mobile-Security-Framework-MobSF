define('10003591_js/finappConfig',[],function(){ return ({
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

define('10003591_js/compiled/finappCompiled',['handlebars'], function(Handlebars) {
  var template = Handlebars.template, templates = Handlebars.templates = Handlebars.templates || {};
templates['noResults'] = template(function (Handlebars,depth0,helpers,partials,data) {
  helpers = helpers || Handlebars.helpers;
  var buffer = "", stack1, stack2, stack3, foundHelper, tmp1, self=this, functionType="function", helperMissing=helpers.helperMissing, undef=void 0, escapeExpression=this.escapeExpression;


  buffer += "<div class=\"row collapse text-centered\">\n	<div class=\"small-12 column noResults\">\n		";
  stack1 = "no_results_found";
  stack2 = {};
  foundHelper = helpers.searchKeyword;
  stack3 = foundHelper || depth0.searchKeyword;
  stack2['_SEARCH_KEY_'] = stack3;
  foundHelper = helpers.__;
  stack3 = foundHelper || depth0.__;
  tmp1 = {};
  tmp1.hash = stack2;
  if(typeof stack3 === functionType) { stack1 = stack3.call(depth0, stack1, tmp1); }
  else if(stack3=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, tmp1); }
  else { stack1 = stack3; }
  buffer += escapeExpression(stack1) + "\n	</div>\n</div>\n                                    ";
  return buffer;});
templates['popularSuggestedSearch'] = template(function (Handlebars,depth0,helpers,partials,data) {
  helpers = helpers || Handlebars.helpers;
  var buffer = "", stack1, stack2, stack3, foundHelper, self=this, functionType="function", helperMissing=helpers.helperMissing, undef=void 0, escapeExpression=this.escapeExpression;


  stack1 = 3;
  stack2 = 1;
  foundHelper = helpers.breadcrumb;
  stack3 = foundHelper || depth0.breadcrumb;
  if(typeof stack3 === functionType) { stack1 = stack3.call(depth0, stack2, stack1, { hash: {} }); }
  else if(stack3=== undef) { stack1 = helperMissing.call(depth0, "breadcrumb", stack2, stack1, { hash: {} }); }
  else { stack1 = stack3; }
  buffer += escapeExpression(stack1) + "\n\n<div class = \"searchContainer\">\n    <form>\n        <div class=\"row collapse searchBoxContainer\" >\n            <div class=\"small-12 medium-9 small-portrait-9 medium-portrait-9  large-10 column\" id=\"search\" >\n                <i id=\"backToPopSugg\" class=\"yodlee-font-icon svg_back_arrow backToPopSugg hide\" aria-label=\"";
  stack1 = "back_button_text";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\" role=\"button\" tabindex=\"0\"></i>\n                <div id=\"searchIcon\"class=\"yodlee-font-icon svg_search searchIcon\" aria-hidden=\"true\"></div>\n                <input id=\"siteSearch\" autocomplete=\"off\"  role=\"search\" title=\"";
  stack1 = "search_box_place_holder_desktop";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\"  autocapitalize=\"off\" type=\"search\" placeholder = \"";
  stack1 = "search_box_place_holder_desktop";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\" />\n                <div  class=\"yodlee-font-icon svg_close searchClose hide\" aria-label=\"";
  stack1 = "clear_search_text";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\" role=\"button\" tabindex=\"0\"></div>\n                \n            </div>\n            <div class=\"medium-3 large-2 small-portrait-3 medium-portrait-3 column hide-for-small-only show-for-small-portrait show-for-medium-portrait\" role=\"button\" id=\"searchBtn\"><input type=\"submit\" class=\"button postfix\" value=\"";
  stack1 = "search_btn_label";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\"/></div>\n        </div>\n        <div id=\"searchInfoContainer\">\n            <div class=\"searchInfoContainer hide-for-small-only show-for-small-portrait show-for-medium-portrait\">\n                <span class=\"searchInfoMsg\" tabindex=\"0\">";
  stack1 = "search_info_msg";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</span><i class=\"yodlee-font-icon svg_info info searchInfo siteTooltip y-tooltip\" tooltip-width=\"280\" tooltip-title=\"";
  stack1 = "search_info_tooltip";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\"  role=\"button\" aria-label=\"search information\" tabindex=\"0\"></i>\n            </div>\n        </div>\n        \n    </form>\n    <div id=\"searchSiteContainer\" style=\"display:none\"></div>\n</div>\n<div id=\"popSuggSiteContainer\">\n    <ul id=\"popSuggestTabs\" class=\"tabs customTabs show-for-small-only hide-for-small-portrait hide-for-medium-portrait\" style=\"display:none\" data-tab role=\"tablist\">\n        <li class = \"tab-title active small-6 suggestedSite\" tabindex=\"0\"><a href=\"#suggestedSiteTabContainer\" class = \"tab-margin-cls\" role=\"tab\" aria-controls=\"panel1\" aria-selected=\"true\" role=\"presentation\">";
  stack1 = "mobile_suggested_accounts";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + " </a></li>\n        <li class=\"tab-title small-6 popularSite\" tabindex=\"0\"><a href=\"#popularSiteTabContainer\" class = \" \" role=\"tab\" aria-controls=\"panel2\" aria-selected=\"false\" role=\"presentation\">";
  stack1 = "mobile_popular_accounts";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</a></li>\n    </ul>\n    <div class=\"tabs-content\" >\n        <div class=\"siteWrapper content active \" id=\"suggestedSiteTabContainer\">\n                    <div class=\"section-title hide-for-small-only show-for-small-portrait show-for-medium-portrait suggestedSite\" role=\"heading\" aria-level=\"2\">\n            ";
  stack1 = "suggested_accounts";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\n                    </div>\n                    <div class=\"suggestedSite\" id=\"suggestedSiteContainer\" ></div>\n        </div>\n        <div class=\"siteWrapper content show-for-small-portrait show-for-medium-portrait\" id=\"popularSiteTabContainer\">\n                    <div class=\"section-title hide-for-small-only show-for-small-portrait show-for-medium-portrait popularSite\" role=\"heading\" aria-level=\"2\">\n            ";
  stack1 = "popular_accounts";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\n                    </div>\n                    <div class=\"show-for-small-portrait popularSite\"  id=\"popularSiteContainer\"></div>\n        </div>\n    </div>\n</div>\n<div id=\"otherAccountsContainer\" class=\"row\">\n    <div class=\"other-title\" role=\"heading\" aria-level=\"2\">\n        ";
  stack1 = "add_other_accounts";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\n    </div>\n    <div class=\"column small-12 otherAccounts\">\n        <div class=\"column small-12 medium-portrait-6 medium-6 medium-min-single-col realState\">\n            <input class=\"button expand secondary\" type=\"button\" value=\"";
  stack1 = "add_real_estate_account";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\"/>\n        </div>\n        <div class=\"column small-12 medium-portrait-6 medium-6 medium-min-single-col otherAccount\">\n            <input class=\"button expand secondary\" type=\"button\" value=\"";
  stack1 = "add_manual_account";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\"/>\n        </div>\n    </div>\n</div>\n";
  return buffer;});
templates['searchSites'] = template(function (Handlebars,depth0,helpers,partials,data) {
  helpers = helpers || Handlebars.helpers;
  var buffer = "", stack1, stack2, foundHelper, tmp1, self=this, functionType="function", helperMissing=helpers.helperMissing, undef=void 0, escapeExpression=this.escapeExpression;

function program1(depth0,data) {
  
  var buffer = "", stack1, stack2, stack3;
  buffer += "\n	<div class=\"searchResults\">\n		";
  stack1 = "search_results_found";
  stack2 = {};
  foundHelper = helpers.searchKeyword;
  stack3 = foundHelper || depth0.searchKeyword;
  stack2['_SEARCH_KEY_'] = stack3;
  foundHelper = helpers.__;
  stack3 = foundHelper || depth0.__;
  tmp1 = {};
  tmp1.hash = stack2;
  if(typeof stack3 === functionType) { stack1 = stack3.call(depth0, stack1, tmp1); }
  else if(stack3=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, tmp1); }
  else { stack1 = stack3; }
  buffer += escapeExpression(stack1) + "\n	</div>\n";
  return buffer;}

function program3(depth0,data) {
  
  
  return "\n		resultsFound\n	";}

function program5(depth0,data) {
  
  
  return "\n		infinateScroll\n	";}

function program7(depth0,data) {
  
  
  return "\n		multiRows\n	";}

  foundHelper = helpers.infinateScroll;
  stack1 = foundHelper || depth0.infinateScroll;
  stack2 = helpers['if'];
  tmp1 = self.program(1, program1, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n<div class=\"searchSiteSubContainer\n	";
  foundHelper = helpers.isResultsFound;
  stack1 = foundHelper || depth0.isResultsFound;
  stack2 = helpers['if'];
  tmp1 = self.program(3, program3, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n	";
  foundHelper = helpers.infinateScroll;
  stack1 = foundHelper || depth0.infinateScroll;
  stack2 = helpers['if'];
  tmp1 = self.program(5, program5, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n	";
  foundHelper = helpers.multiRows;
  stack1 = foundHelper || depth0.multiRows;
  stack2 = helpers['if'];
  tmp1 = self.program(7, program7, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "	\n\">\n	<div id=\"searchSites\" class=\"row siteList searchSites collapse\"></div>\n</div>";
  return buffer;});
templates['site'] = template(function (Handlebars,depth0,helpers,partials,data) {
  helpers = helpers || Handlebars.helpers;
  var buffer = "", stack1, stack2, stack3, stack4, foundHelper, tmp1, self=this, functionType="function", helperMissing=helpers.helperMissing, undef=void 0, escapeExpression=this.escapeExpression, blockHelperMissing=helpers.blockHelperMissing;

function program1(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n		<div class=\"small-1 medium-1 large-1 column favicon\">\n		    <div aria-hidden=\"true\">\n		    <img src=\"";
  stack1 = "site_favicon_url";
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
  buffer += escapeExpression(stack1) + "\"/></div>\n		</div>\n	";
  return buffer;}

function program3(depth0,data) {
  
  
  return "\n		<div class=\"small-9 medium-9 large-10 column siteInfo\">\n	";}

function program5(depth0,data) {
  
  
  return "\n		<div class=\"small-10 medium-9 large-10 column siteInfo\">\n	";}

function program7(depth0,data) {
  
  var buffer = "", stack1, stack2;
  buffer += "\n		<div class=\"small-2 medium-2 large-1 column end tooltipIcon\">\n			<i class=\"yodlee-font-icon svg_success tickmark\"></i>\n			<div class=\"message\">";
  stack1 = "status_added";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</div>\n		</div>\n	";
  return buffer;}

function program9(depth0,data) {
  
  var buffer = "", stack1, stack2, stack3, stack4;
  buffer += "\n		<div class=\"small-1 medium-1 large-1 column tooltipIcon\">\n			";
  stack1 = "true";
  stack2 = "==";
  stack3 = "site_level_tooltip_enabled";
  foundHelper = helpers.ifCond;
  stack4 = foundHelper || depth0.ifCond;
  tmp1 = self.program(10, program10, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  if(foundHelper && typeof stack4 === functionType) { stack1 = stack4.call(depth0, stack3, stack2, stack1, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack4, stack3, stack2, stack1, tmp1); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n		</div>\n	";
  return buffer;}
function program10(depth0,data) {
  
  var buffer = "", stack1, stack2, stack3;
  buffer += "\n			    <a href=\"#\"class=\"yodlee-font-icon svg_info info siteTooltip y-tooltip\" tooltip-width=\"200\" tooltip-title=\"";
  stack1 = "site_tooltip";
  stack2 = {};
  foundHelper = helpers.displayName;
  stack3 = foundHelper || depth0.displayName;
  stack2['_SITE_NAME_'] = stack3;
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
  buffer += escapeExpression(stack1) + "\" tabindex=\"0\" role=\"button\"><span class=\"ada-offscreen\">";
  stack1 = "info_button_text";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</span></a>\n\n			";
  return buffer;}

  buffer += "<div class=\"row site-item collapse\">\n	";
  stack1 = "true";
  stack2 = "==";
  stack3 = "show_account_favicon";
  foundHelper = helpers.ifCond;
  stack4 = foundHelper || depth0.ifCond;
  tmp1 = self.program(1, program1, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.noop;
  if(foundHelper && typeof stack4 === functionType) { stack1 = stack4.call(depth0, stack3, stack2, stack1, tmp1); }
  else { stack1 = blockHelperMissing.call(depth0, stack4, stack3, stack2, stack1, tmp1); }
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n	";
  foundHelper = helpers.isAlreadyAddedByUser;
  stack1 = foundHelper || depth0.isAlreadyAddedByUser;
  stack2 = helpers['if'];
  tmp1 = self.program(3, program3, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.program(5, program5, data);
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n	    <div class =\"siteName\" role=\"tab\" tabindex=\"0\" orgValue=\"";
  foundHelper = helpers.displayName;
  stack1 = foundHelper || depth0.displayName;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "displayName", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\">";
  foundHelper = helpers.displayName;
  stack1 = foundHelper || depth0.displayName;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "displayName", { hash: {} }); }
  buffer += escapeExpression(stack1) + "</div>\n	    <div class =\"siteUrl ellipsis-cls\" title=\"";
  foundHelper = helpers.baseUrl;
  stack1 = foundHelper || depth0.baseUrl;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "baseUrl", { hash: {} }); }
  buffer += escapeExpression(stack1) + "\">";
  foundHelper = helpers.baseUrl;
  stack1 = foundHelper || depth0.baseUrl;
  if(typeof stack1 === functionType) { stack1 = stack1.call(depth0, { hash: {} }); }
  else if(stack1=== undef) { stack1 = helperMissing.call(depth0, "baseUrl", { hash: {} }); }
  buffer += escapeExpression(stack1) + "</div>\n	</div>\n	";
  foundHelper = helpers.isAlreadyAddedByUser;
  stack1 = foundHelper || depth0.isAlreadyAddedByUser;
  stack2 = helpers['if'];
  tmp1 = self.program(7, program7, data);
  tmp1.hash = {};
  tmp1.fn = tmp1;
  tmp1.inverse = self.program(9, program9, data);
  stack1 = stack2.call(depth0, stack1, tmp1);
  if(stack1 || stack1 === 0) { buffer += stack1; }
  buffer += "\n</div>\n";
  return buffer;});
return templates;
});
define('10003591_js/views/popularSuggestedSearchView',['10003591_js/compiled/finappCompiled'], function(templates) {
    var PopularSuggestedSearchView = Backbone.Marionette.LayoutView.extend({
        initialize: function(options) {
            this.moduleKey = options.moduleKey
            this.isPlaceholderSupported = 'placeholder' in document.createElement('input')
        },
        ui: {
            'searchBox': '#siteSearch',
            'search': '#search',
            'popSection': '#popSuggSiteContainer',
            'otherSection' : '#otherAccountsContainer',
            'searchSection': '#searchSiteContainer',
            'searchClose' : '.searchClose',
            'searchBtn' : '#searchBtn',
            'backToPopSugg' : '#backToPopSugg',
            'searchIcon' : '#searchIcon'
        },
        template: templates['popularSuggestedSearch'],

        events: {
            'keyup @ui.searchBox': 'searchResultsByKeyUP',
            'focus @ui.searchBox': 'showSearchPanel',
            'blur @ui.searchBox': 'showPlaceHolder',
            'click @ui.searchClose' : 'clearSearchResultsAndFocus',
            'submit' : "handleSearchFormSubmit",
            'click @ui.backToPopSugg' : 'backToHomePage'
        },

        regions: {
            popularSiteContainer: '#popularSiteContainer',
            suggestedSiteContainer: '#suggestedSiteContainer',
            searchSiteContainer: '#searchSiteContainer'
        },

        showSearchPanel: function(e) {
            this.removePlaceHolder();
            this.ui.search.removeClass('showClose');
            this.ui.backToPopSugg.removeClass('hide');
            
            $('.FL').addClass('searchMode');
            this.ui.popSection.hide();
            this.ui.otherSection.hide();
            this.ui.searchSection.show();
            this.ui.searchIcon.addClass('hide');
            yo.closeBubbleTooltip();
        },

        hidePopularSiteSection : function() {
            this.$el.find('.popularSite').removeClass().addClass('hide');
            this.$el.find('dd.suggestedSite').addClass('small-12').addClass('active');
            this.$el.find('#suggestedSiteTabContainer').addClass('content').addClass('active');
            this.$el.find('#popularSiteTabContainer').addClass('hide');
        },

        hideSuggestedSiteSection : function() {
            Logger.debug('Hiding suggested site section.'+this.$el.find('.suggestedSite'));
            this.$el.find('.suggestedSite').removeClass().addClass('hide');
            this.$el.find('dd.popularSite').addClass('small-12').addClass('active');;
            this.$el.find('#popularSiteTabContainer').addClass('content').addClass('active');
            this.$el.find('#suggestedSiteTabContainer').addClass('hide');
        },

        searchResultsByKeyUP: function() {
            var currentString = $.trim(this.ui.searchBox.val());
            if( currentString.length > 0 ) {
                this.ui.searchBox.addClass('searchPaddingRight');                
                this.ui.searchClose.removeClass('hide');
                this.ui.search.addClass('showClose');
                this.showResultsTypeHead();                
            } else {
                this.clearSearchResults();
            }
        },

        showResultsTypeHead :  _.debounce(function() {
                this.searchResults( 3, false );
            }, 300),

        handleSearchFormSubmit : function(e){
            e.preventDefault();

            this.searchResults(1, true);
            this.$el.find('#siteSearch').focusout();
            return false;
        },

        showPlaceHolder : function() {
            if( !this.isPlaceholderSupported ) {
                var currentString = $.trim(this.ui.searchBox.val());
                if( currentString.length == 0 ) {
                    var value = this.ui.searchBox.attr('placeholder');
                    Logger.debug('Place holder text : '+value);
                    this.ui.searchBox.val(value);
                    this.ui.searchBox.addClass('placeholder');
                }
            }
        },

        removePlaceHolder : function() {
            if( !this.isPlaceholderSupported && this.ui.searchBox.hasClass('placeholder') ) {
                this.ui.searchBox.val('');
                this.ui.searchBox.removeClass('placeholder');
            }
        },

        searchResults: function( minChars, infinateScroll) {
            if( this.isPlaceholderSupported || !this.ui.searchBox.hasClass('placeholder') ) {
                var currentString = $.trim(this.ui.searchBox.val());
                if( currentString != '' && this.prevString != currentString && currentString.length >= minChars ) {
                    this.prevString = currentString;
                    Application.AppRouter.route(this.moduleKey, 'searchSiteResults', false, {'searchKey': this.ui.searchBox.val(), 'infinateScroll' : infinateScroll});
                } else if( currentString != '' && infinateScroll == true ) {
                    this.prevInfinateScroll = infinateScroll
                    Application.AppRouter.route(this.moduleKey, 'searchSiteResults', false, {'searchKey': this.ui.searchBox.val(), 'infinateScroll' : infinateScroll});
                } else if( currentString != '' && this.prevString != currentString ){
                    this.$el.find(this.regions.searchSiteContainer).html('');
                }
            }
        },

        clearSearchResultsAndFocus: function() {
            this.clearSearchResults();
            this.ui.searchBox.focus();
        },

        clearSearchResults : function() {
            this.ui.searchClose.addClass('hide');
            this.ui.search.removeClass('showClose');
            this.ui.searchBox.removeClass('searchPaddingRight');
            this.ui.searchBox.val('');
            this.$el.find(this.regions.searchSiteContainer).html('');
            this.prevString = '';
            Application.AppRouter.route(this.moduleKey, 'abortSearchSiteResults');
        },

        backToHomePage: function() {
            this.clearSearchResults();
            this.ui.backToPopSugg.addClass('hide');
            this.ui.searchIcon.removeClass('hide');
            $('.FL').removeClass('searchMode');
            this.ui.popSection.show();
            this.ui.otherSection.show();
            this.ui.searchSection.hide();
            this.prevString = null;
            this.showPlaceHolder();
        },

        onShow: function() {
            var deviceInfo = Utilities.getDeviceInfo();
            if(deviceInfo.type == MOBILE) {
                placeHolderText = Utilities.getString('search_box_place_holder_mobile');
            } else if( deviceInfo.type == TABLET ) {
                if( deviceInfo.mode == PORTRAIT ) {
                    placeHolderText = Utilities.getString('search_box_place_holder_tablet_portrait');
                } else {
                    placeHolderText = Utilities.getString('search_box_place_holder_tablet');
                }
                Utilities.addOrientationEvent(function(mode) {
                    var placeHolderText = '';
                    if( mode == PORTRAIT ) {
                        placeHolderText = Utilities.getString('search_box_place_holder_tablet_portrait');
                    } else {
                        placeHolderText = Utilities.getString('search_box_place_holder_tablet');
                    }
                    $('#siteSearch').attr('placeholder', placeHolderText);
                })
            } else {
                placeHolderText = Utilities.getString('search_box_place_holder_desktop');
            }
            $('#siteSearch').attr('placeholder', placeHolderText);            
            $(document).foundation();
            $('#popSuggestTabs').on('toggled', function (event, tab) {
                 
                  currentElement =$(event.target);
                $('#popSuggestTabs').find('a').attr('aria-selected','false')
                $(currentElement).find('.active').find('a').attr('aria-selected','true')
                 Utilities.ellipsify('#popSuggSiteContainer .siteName');


            });
            this.showPlaceHolder();
        }
    });
    return PopularSuggestedSearchView;
});
define('10003591_js/views/siteView',['10003591_js/compiled/finappCompiled'], function(templates) {
	var SiteView = Backbone.Marionette.ItemView.extend({

		initialize : function(options) {
			this.moduleKey = options.moduleKey;
			this.index = options.childIndex;
			this.size = options.size;
		},

		template: templates['site'],

		className : 'small-12 medium-portrait-6 medium-6 medium-min-split-cols-2 large-6 columns',

		showLoginForm : function() {
			var data = { 'siteInfo' : this.model.toJSON() };
			$('.FL').removeClass('searchMode');
			Application.AppRouter.route( this.moduleKey, 'loadSiteLoginFormModule', true, data);
		},

		events : {
			'click .siteName': 'showLoginForm',
			'keydown .siteName' : 'keyupForsiteName'
		},
		keyupForsiteName : function( e ) {
			if(e.keyCode == "13"){
				this.showLoginForm();
			}
		},

		onShow : function() {
			if( this.size == (this.index +1)) {
				this.$el.addClass('end');
			}
			if( this.index == 0 ) {
				this.$el.addClass('start');	
			}
		}
	});
	return SiteView;
});
define('10003591_js/views/siteListView',['10003591_js/views/siteView'], function(SiteView) {
	var SiteListView = Backbone.Marionette.CollectionView.extend({

		initialize : function(options) {
			this.moduleKey = options.moduleKey;
		},

		childViewOptions: function(model, index) {
			return {
    			childIndex : index,
    			moduleKey : this.moduleKey,
    			size : this.collection.size()
    		}
  		},

		childView: SiteView,

		className: 'row siteList collapse',

		onShow : function() {
			yo.bubbleTooltip();
			Utilities.ellipsify( '#popSuggSiteContainer .siteName', true );
		}

	});
	return SiteListView;
});
define('10003591_js/models/site',[], function() {
    var Site = Backbone.Model.extend({
        defaults: {
            displayName : '',
            baseUrl : '',
            loginUrl : '',
            containers : '',
            siteId : 0,
            siteLevelHelpText : '',
            isAlreadyAddedByUser : false
        }
  });
  return Site;
});
define('10003591_js/common/dataParser',[], function() {
    
	var DataParser = function(){

		var POPULAR_SITES_API = "popularSites";
		var SUGGSTED_SITES_API = "suggestedSites";
		var SEARCH_SITES_API = "searchSites";

		var _parseSites = function( response ) {
			var result = [];
			if( response && response.length ) {
				for( var i in response ) {
					result[i] = _parseSite(response[i]);
				}
			}
			return result;
		};

		var _parseSite = function( response ) {
			var result = {};
			if( typeof response != 'undefined' && response ) {
				result.siteId = response.siteId;
				result.displayName = response.defaultDisplayName;
				result.baseUrl = response.baseUrl;
				result.siteLevelHelpText = response.defaultHelpText;
				result.isAlreadyAddedByUser = response.isAlreadyAddedByUser;
				if( response.contentServiceInfos ) {
					$.each(response.contentServiceInfos, function(key, val) {
	            		if( !result.loginUrl && val.loginUrl ) {
	            			result.loginUrl = val.loginUrl;
	            		}
	            		var containerName = Utilities.getString('tag_'+val.containerInfo.containerName.toLowerCase()+'_name');
	            		if( !result.containers ) {
	            			result.containers = containerName;
	            		} else {
	            			result.containers += ', '+ containerName;
	            		}
	        		});
	        	}
				return result;
			}
			return result;
		};

		var _getPopularSitesInputData = function( popSiteLevel ) {
			if( isNaN(popSiteLevel) || popSiteLevel <= 0 || popSiteLevel > 4 ) {
				popSiteLevel = 4;
			}
			var result = {};
			result.data = {'siteFilter.siteLevel.popSiteLevel': ''+popSiteLevel+'', 'notrim' : 'true'}
			result.method = 'POST';
			result.apiUrl = POPULAR_SITES_API;
			return result;
		}

		var _getSuggestedSitesInputData = function() {
			var result = {};
			result.data = {'notrim' : 'true'}
			result.method = 'POST';
			result.apiUrl = SUGGSTED_SITES_API;
			return result;
		};

		var _getGraphInputData = function(popularSitesEnabled, popSiteLevel) {
			var graphInput = {};
			var index = 0;
			if( popularSitesEnabled ) {
				graphInput[index++]  = _getPopularSitesInputData(popSiteLevel);
			}
			graphInput[index++] = _getSuggestedSitesInputData();
			return graphInput;
		}		

		var _getSearchSitesSitesInputData = function(searchString) {
			var result = {};
			result.method = 'POST';
			result.data = {'siteSearchString':searchString, 'notrim' : 'true'};
			result.apiUrl = SEARCH_SITES_API;
			return result;
		};		

		return {
	        parseSites : _parseSites,
	        getGraphInputData : _getGraphInputData,
	        getSuggestedSitesInputData : _getSuggestedSitesInputData,
	        getSearchSitesSitesInputData : _getSearchSitesSitesInputData
	    }
	}
	return new DataParser();
});

define('10003591_js/collections/sites',['10003591_js/models/site','10003591_js/common/dataParser'], function(Site, DataParser) {
	var Sites = Backbone.Collection.extend({
		model: Site,

		parse : function(response) {
			if( !response.length ) {
				response = [];
			}
			return DataParser.parseSites(response);
		}
	});
  return Sites;
});
define('10003591_js/views/searchSiteView',['10003591_js/views/siteView'], function(SiteView) {
	var SearchSiteView = SiteView.extend({

		className : 'small-12 medium-12 large-12 columns'

	});
	return SearchSiteView;
});
define('10003591_js/views/noResultsView',['10003591_js/compiled/finappCompiled'], function(templates) {
	var SiteView = Backbone.Marionette.ItemView.extend({

		initialize : function(options) {
  			this.templateHelpers.searchKeyword = options.searchKey;
		},

		template: templates['noResults'],

	    templateHelpers: {
        	searchKeyword: ''
        }		

	});
	return SiteView;
});
define('10003591_js/views/searchSiteListView',['10003591_js/compiled/finappCompiled', '10003591_js/views/siteListView', '10003591_js/views/searchSiteView', '10003591_js/views/noResultsView'], 
	function(templates, SiteListView, SearchSiteView, NoResultsView) {
	var SearchSiteListView = Backbone.Marionette.CompositeView.extend({

		DEFAULT_RESULTS_PER_PAGE : 20,
		DEFAULT_TYPE_HEAD_RESULTS : 10,

		searchKey : '',

		initialize : function(options) {
			this.templateHelpers.searchKeyword = this.searchKey = options.searchKey;
			this.moduleKey = options.moduleKey;
			this.cacheCollection = this.collection.clone();
			this.collectionSize = this.cacheCollection.size();
			this.infinateScroll = options.infinateScroll;
			this.templateHelpers.isResultsFound = ( this.collection.size() != 0 );
			if( this.collection.size() > 1 ) {
				this.templateHelpers.multiRows = ( this.collection.size() > 1 );
							
				if( this.infinateScroll == true ) {
					this.templateHelpers.infinateScroll = true;
					this.sitesPerPage = this.lastElementId = this.getSitesPerPage();			
					this.collection.set(this.cacheCollection.slice(0, this.sitesPerPage));
					this.firstElementId = 1;
					this.contentsHeight = 0;
				} else {
					this.templateHelpers.infinateScroll = false;
					this.collection.set(this.cacheCollection.slice(0, this.getSitesForTypeHead()));
				}
			} else {
				this.templateHelpers.infinateScroll = false;
			}
			this.processing = false;
		},

		childViewContainer : '#searchSites',

		childView: SearchSiteView,

		emptyView : NoResultsView,

		template: templates['searchSites'],

		emptyViewOptions: function() {
			return {
    			searchKey : this.searchKey
    		}
  		},

		childViewOptions: function(model, index) {
			return {
    			childIndex : index,
    			moduleKey : this.moduleKey,
    			size : this.collection.size()
    		}
  		},  		

		className: '',

		getSitesForTypeHead : function() {
			var val = 0;
            var deviceInfo = Utilities.getDeviceInfo();
			if( deviceInfo.type == MOBILE ) {
                val = Utilities.getParam('search_results_mobile_type_head');
            } else if( deviceInfo.type == TABLET ) {
                val = Utilities.getParam('search_results_tablet_type_head');
            } else {
                val = Utilities.getParam('search_results_desktop_type_head');
            }
			if( isNaN(val) || val < 1  ) {
				Logger.warn('Assigning default value 10 in place of '+val);
				val = DEFAULT_TYPE_HEAD_RESULTS;
			}
			return parseInt(val);
		},

		getSitesPerPage : function() {
			var val = 0;
            var deviceInfo = Utilities.getDeviceInfo();
			if( deviceInfo.type == MOBILE ) {
                val = Utilities.getParam('search_results_mobile_per_page');
            } else if( deviceInfo.type == TABLET ) {
                val = Utilities.getParam('search_results_tablet_per_page');
            } else {
                val = Utilities.getParam('search_results_desktop_per_page');
            }
			if( isNaN(val) || val < 20 || val > 50 ) {
				Logger.warn('Assigning default value 10 in place of '+val);
				val = DEFAULT_RESULTS_PER_PAGE;
			}
			return parseInt(val);
		},

    	showNextSearchResults: function(){
    		var searchContainer = Application.Appcore.getElement(this.moduleKey, '.searchSiteSubContainer');
      		if(searchContainer.scrollTop() + searchContainer.height() >= this.contentsHeight) {

      			if( this.lastElementId < this.collectionSize ) {
					searchContainer.children('.lazyLoading:last-child').show();
      			}
      			this.lastElementId = this.lastElementId + this.sitesPerPage;

				if( this.lastElementId >= this.collectionSize ) {
					this.lastElementId = this.collectionSize;
					searchContainer.children('.lazyLoading:last-child').hide();
				}

				if( (this.lastElementId - this.firstElementId) > 100 ) {
					this.firstElementId = this.firstElementId + 50;
					searchContainer.children('.lazyLoading:first-child').show();
				}

        		this.collection.set(this.cacheCollection.slice(this.firstElementId, this.lastElementId));
				this.contentsHeight = $('.searchSiteSubContainer').children('.searchSites').height();

	        } else if( searchContainer.scrollTop() <= 0 ) {
	        	if( this.firstElementId > 0 ) {
					searchContainer.children('.lazyLoading:first-child').show();
				}
				this.firstElementId = this.firstElementId - this.sitesPerPage;
				if( this.firstElementId < 0 ) {
					this.firstElementId = 0;
					searchContainer.children('.lazyLoading:first-child').hide();
				}
				if( (this.lastElementId - this.firstElementId) > 100 ) {
					this.lastElementId = this.lastElementId - 50;
				}

        		this.collection.set(this.cacheCollection.slice(this.firstElementId, this.lastElementId));
				this.contentsHeight = $('.searchSiteSubContainer').children('.searchSites').height();	
				if( this.firstElementId > 0 ) {
					searchContainer.scrollTop(this.defaultConentHeight)					
				}								
	        }
    	},

		onShow : function() {
			yo.bubbleTooltip();
			Utilities.ellipsify( '.searchSites .siteName', true );
			var searchContainer = Application.Appcore.getElement(this.moduleKey, '.searchSiteSubContainer');
			if( this.infinateScroll == true ) {
				var self = this;
				this.contentsHeight = this.defaultConentHeight = searchContainer.children('.searchSites').height();

				if( this.collectionSize > this.sitesPerPage ) {
					searchContainer.prepend("<div class='lazyLoading' style='display:none'>"+Utilities.getString('pre_search_loading_msg')+"</div>")
					searchContainer.append("<div class='lazyLoading'>"+Utilities.getString('post_search_loading_msg')+"</div>")
					searchContainer.scroll(function() {
						if( !self.processing ) {
							self.processing = true;
							setTimeout( function() {
	    	            		self.showNextSearchResults();
	    	            		Utilities.ellipsify( '.searchSites .siteName', true );
	    	            		self.processing = false
							}, 300)

	    	            }
	        	    });
	        	}
	        }
	    },

	    templateHelpers: {
        	searchKeyword: '',
        	isResultsFound : false,
        	infinateScroll : false,
        	multiRows : false
        }
	});
	return SearchSiteListView;
});
define('10003591_js/controller/siteController',['10003591_js/views/popularSuggestedSearchView'
            , '10003591_js/views/siteListView'
            , '10003591_js/collections/sites'
            , '10003591_js/views/searchSiteView'
            , '10003591_js/views/searchSiteListView'
            , '10003591_js/common/dataParser'],
        function(PopularSuggestedSearchView, SiteListView, Sites, SearchSiteView, SearchSiteListView, DataParser) {
            var SiteController = Backbone.Marionette.Controller.extend({

                DEFAULT_POPULAR_SITES_MAX_LIMIT : 5,

                DEFAULT_SUGGESTED_SITES_MAX_LIMIT : 3,
                
                initialize: function(options) {
                    Logger.debug('Site Controller is initialized...');
                    this.moduleKey = options.moduleKey;
                },

                start: function(options) {

                    var self = this;
                    this.region = options.region;
                    yo.inlineSpinner.show(this.region.el);
                    this.loadPopularSites = false;
                    this.loadSuggestedSites = false;
                    this.suggestedSitesEnabled = false;
                    this.popularSitesEnabled = this.isPopularSitesEnabled();
                    this.getGraphData()
                },

                getGraphData : function() {
                    Logger.debug("Calling graph data for Popular Suggested View.");
                    var self = this;
                    var graphInputData = DataParser.getGraphInputData(this.popularSitesEnabled, Utilities.getParam('popular_site_level') );
                    graphInputData = Application.Wrapper.formatGraphInputData(graphInputData); 
                    Application.YGraph.build( graphInputData, function( graphData ) {
                        self.loadPopularSitesData( graphData['InternalPassThroughMakeCall_popularSites'] );
                        self.loadSuggestedSitesData( graphData['InternalPassThroughMakeCall_suggestedSites'] );
                        self.showPopularSuggestedSites();
                    });
                },

                loadPopularSitesData : function( popularSitesData ) {
                    if( this.popularSitesEnabled ) {
                        this.popularSites = new Sites();
                        this.popularSites.set(DataParser.parseSites(popularSitesData));
                    }
                },

                loadSuggestedSitesData : function( suggestedSitesData ) {
                    this.suggestedSites = new Sites();
                    this.suggestedSites.set(DataParser.parseSites(suggestedSitesData));
                    this.loadSuggestedSites = true;
                },

                showPopularSuggestedSites : function() {
                    Logger.debug(this.loadPopularSites+'show PopularSuggestedSearchView '+this.loadSuggestedSites)

                    yo.inlineSpinner.hide(this.region.el);
                    this.popularSuggestedSearchView = new PopularSuggestedSearchView({moduleKey: this.moduleKey});
                    this.region.show(this.popularSuggestedSearchView);

                    if( this.popularSitesEnabled && this.popularSites.size() > 0 ) {
                        var val = 0;
                        var deviceInfo = Utilities.getDeviceInfo();
                        if( deviceInfo.type == MOBILE ) {
                            val = Utilities.getParam('popular_sites_mobile_max_limit');
                        } else if( deviceInfo.type == TABLET ) {
                            val = Utilities.getParam('popular_sites_tablet_max_limit');
                        } else {
                            val = Utilities.getParam('popular_sites_desktop_max_limit');
                        }
                        if( isNaN(val) || val <= 0  ) {
                            Logger.warn('Assigning popular sites default value 10 in place of '+val);
                            val = this.DEFAULT_POPULAR_SITES_MAX_LIMIT;
                        }   
                        this.popularSites.set(this.popularSites.slice(0, val));
                        var siteListView = new SiteListView({collection: this.popularSites, moduleKey : this.moduleKey});
                        this.popularSuggestedSearchView.popularSiteContainer.show(siteListView);
                    } else {
                        this.popularSuggestedSearchView.hidePopularSiteSection();
                    }

                    if( this.suggestedSites.size() > 0 ) {
                        var val = 0;
                        var deviceInfo = Utilities.getDeviceInfo();
                        if( deviceInfo.type == MOBILE ) {
                            val = Utilities.getParam('suggested_sites_mobile_max_limit');
                        } else if( deviceInfo.type == TABLET ) {
                            val = Utilities.getParam('suggested_sites_tablet_max_limit');
                        } else {
                            val = Utilities.getParam('suggested_sites_desktop_max_limit');
                        }                        
                        if( isNaN(val) || val <= 0  ) {
                            Logger.warn('Assigning suggested Sites default value 10 in place of '+val);
                            val = this.DEFAULT_SUGGESTED_SITES_MAX_LIMIT;
                        }   
                        this.suggestedSites.set(this.suggestedSites.slice(0, val));                                                
                        var siteListView = new SiteListView({collection: this.suggestedSites, moduleKey : this.moduleKey});
                        this.popularSuggestedSearchView.suggestedSiteContainer.show(siteListView);
                    } else {
                        this.popularSuggestedSearchView.hideSuggestedSiteSection();
                    }
                },

                abortSearchSiteResults: function() {
                    if( this.xhr ) {
                        this.xhr.abort();
                        this.xhr = null;
                    }
                    this.searchKey = '';
                },

                searchSiteResults: function(options) {
                    var self = this;

                    this.abortSearchSiteResults();

                    this.searchKey = options.searchKey;
                    this.infinateScroll = options.infinateScroll;
                    var apiInfo = Application.Wrapper.getAPIDetails(DataParser.getSearchSitesSitesInputData(options.searchKey));                    
                    var searchSites = new Sites();

                    this.xhr = searchSites.fetch({reset: true,
                        url: apiInfo.url,
                        method : apiInfo.method,
                        data : apiInfo.data,
                        searchKey : this.searchKey,
                        beforeSend : function(){
                            yo.inlineSpinner.show(self.popularSuggestedSearchView.searchSiteContainer.el);
                        },
                        success: function(collections, response, options) {
                            if( options.searchKey === self.searchKey ) {
                                var searchSiteListView = new SearchSiteListView({collection: searchSites, 
                                        searchKey : Utilities.htmlEncode(self.searchKey),
                                        moduleKey : self.moduleKey,
                                        infinateScroll : self.infinateScroll});
                                self.popularSuggestedSearchView.searchSiteContainer.show(searchSiteListView)
                            }
                        },
                        error: function(xhr, status, errorThrown) {
                            Logger.error('Error in search sites.' + status);
                        },
                        complete: function() {
                            yo.inlineSpinner.hide(self.popularSuggestedSearchView.searchSiteContainer.el);
                        }
                    });
                },

                isPopularSitesEnabled : function() {
                    var value = Utilities.getParam('popular_sites_enabled');
                    if( value == 'true' || value === true ) {
                        return true;
                    }
                    return false;
                }
            });
            return SiteController;
        }); 
define('10003591_js/finapp',['10003591_js/controller/siteController'], function(SiteController) {
	var module = Application.Appcore.Module.extend({
		controller : SiteController
	});
	return module;
});

