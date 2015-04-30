define('10003600_js/finappConfig',[],function(){ return ({
    id : "10003600",
    dependsModule : ['10003591'],
   	dependsJs : ['/js/accountParseHandler.js'],
    "modules" : [
		{
			"id" : "10003591",
			"name" : "Popular-Suggested",
			"version" : "latest"
		},
		{
			"id" : "10003592",
			"name" : "Site Login Form",
			"version" : "latest"
		},
		{
			"id" : "10003593",
			"name" : "Site Refresh Status",
			"version" : "latest"
		},
		{
			"id" : "10003594",
			"name" : "Site Account Status",
			"version" : "latest"
		},
		{
			"id" : "10003595",
			"name" : "My Accounts",
			"version" : "latest"
		}
	]
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

define('10003600_js/compiled/finappCompiled',['handlebars'], function(Handlebars) {
  var template = Handlebars.template, templates = Handlebars.templates = Handlebars.templates || {};
templates['FLLayout'] = template(function (Handlebars,depth0,helpers,partials,data) {
  helpers = helpers || Handlebars.helpers;
  var buffer = "", stack1, stack2, foundHelper, self=this, functionType="function", helperMissing=helpers.helperMissing, undef=void 0, escapeExpression=this.escapeExpression;


  buffer += "<div class=\"row mainBody\">\n	<div class=\"small-12 medium-5 medium-min-6 large-4 columns hide-for-small-only leftSection padding-margin-zero\">\n	    <div class=\"row header\">\n			<div class=\"small-3 column show-for-small-only\">\n            	<div id=\"accountsBack\" class=\"yodlee-font-icon svg_back backIcon\" aria-label=\"";
  stack1 = "back_button_text";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\" role=\"button\"></div>\n            </div>			\n			<div class=\"small-6 medium-12 large-12 column\">\n				<div class=\"multiAccountHeaderTitle\" role=\"heading\" aria-level=\"1\">";
  stack1 = "my_accounts";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</div>\n			</div>\n			<div class=\"small-3 column show-for-small-only\">\n				<span>&nbsp;</span>\n			</div>\n		</div>\n        <div id=\"leftContent\" class=\"panel card\"></div>\n	</div>\n	<div class=\"small-12 medium-7 medium-min-6 large-8 columns rightSection padding-margin-zero\">\n        <div class=\"row header collapse\">\n            <div class=\"small-2 medium-2 large-1 column show-for-small-only hide-for-small-portrait hide-for-medium-portrait\">\n            	<i id=\"homeBack\" class=\"yodlee-font-icon svg_back backIcon\" aria-label=\"";
  stack1 = "back_button_text";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\" role=\"button\"></i>\n            </div>\n            <div class=\"small-8 medium-8 large-10 small-portrait-offset-2 medium-offset-2 large-offset-1 column\">\n                <div class=\"singleAccountHeaderTitle show-for-small-only hide-for-medium-portrait hide-for-small-portrait\" role=\"heading\" aria-level=\"1\">";
  stack1 = "add_account";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</div>\n                <div class=\"multiAccountHeaderTitle show-for-medium-up show-for-medium-portrait show-for-small-portrait\" role=\"heading\" aria-level=\"1\">";
  stack1 = "add_account";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</div>\n            </div>\n            <div class=\"small-2 medium-2 large-1 column hide\"><div class=\"closeIcon\"></div></div>\n            <div class=\"small-2 medium-2 large-1 column show-for-small-only\"><i class=\"yodlee-font-icon svg_history myAccountsIcon\" aria-label=\"";
  stack1 = "home_button_text";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\" role=\"button\"></i>\n            </div>\n        </div>\n        <div class=\"headerBtns topHeader row collapse\" style=\"display:none\">\n			<div class=\"column small-12 medium-portrait-6 medium-6 medium-min-12 manageAccountCntr hide\" id=\"manageAccBtn\">\n		  		<input class=\"button expand primary\" type=\"button\" value=\"";
  stack1 = "manage_accounts";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\" id=\"\" />\n			</div>\n			<div class=\"column small-12 medium-portrait-6 medium-6 medium-min-12 otherAccountCntr right hide\" id=\"addAnotherAccBtn\">\n				<input class=\"button expand secondary\" type=\"button\" value=\"";
  stack1 = "add_another_account";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\" id=\"\" />\n			</div>\n		</div>\n        <div id=\"rightContent\" class=\"panel card\"></div>\n	</div>\n</div>\n<div class=\"row footer collapse\">\n	<div class=\"small-12 medium-7 medium-min-6 large-8 medium-offset-5 medium-min-offset-6 large-offset-4 columns\">\n		<div class=\"row collapse right-footer-section\">\n			<div class=\"small-12 small-portrait-1 small-portrait-text-left medium-portrait-text-left medium-text-left medium-text-left large-text-left large-1 medium-1 logos columns center\">\n				<a href=\"#\" aria-label=\"";
  stack1 = "trust_icon_text";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "\"><img src=\"../../../img/truste.png\"/></a>\n			</div>\n			<div class=\"small-12 small-portrait-11 large-11  medium-11  small-12 columns\">\n				<div class=\"small-text-center small-portrait-text-right medium-portrait-text-right medium-text-right\">\n					<i class=\"yodlee-font-icon svg_privacy-sheild privacySheild\" aria-hidden=\"true\"></i><span class=\"links\"><a href=\"#\" class=\"privacySecurity\">";
  stack1 = "privacy_policy";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</a> <span aria-hidden=\"true\">|</span> <a href=\"#\">";
  stack1 = "how_we_protect_you";
  foundHelper = helpers.__;
  stack2 = foundHelper || depth0.__;
  if(typeof stack2 === functionType) { stack1 = stack2.call(depth0, stack1, { hash: {} }); }
  else if(stack2=== undef) { stack1 = helperMissing.call(depth0, "__", stack1, { hash: {} }); }
  else { stack1 = stack2; }
  buffer += escapeExpression(stack1) + "</a></span>\n				</div>\n			</div>\n		</div>\n	</div>\n</div>\n\n";
  return buffer;});
return templates;
});
define('10003600_js/views/FLLayoutView',['10003600_js/compiled/finappCompiled'], function(templates) {
    var FLLayoutView = Backbone.Marionette.LayoutView.extend({

        className : 'flContainer FL',

        template : templates['FLLayout'],

        regions : {
            rightContent: "#rightContent",
            leftContent: "#leftContent"
        },

        events : {
            "click .closeIcon" : 'closeApplication',
            "click #homeBack" : 'loadHomeView',
            "click .myAccountsIcon" : 'showMyAccountsView',
            "click #accountsBack" : 'showHomeView',
            "click #addAnotherAccBtn" : "loadHomeView"
        },

    	initialize : function(options) {
    		Logger.debug('FLLayoutView is initialized.');
    		this.moduleKey = options.moduleKey;
      	},

        onShow : function() {
            $(document).foundation();
			yo.closeBubbleTooltip();
            Application.AppRouter.route(this.moduleKey, 'showHomeView' );
			Application.AppRouter.route(this.moduleKey, 'loadMyAccountsModule' );
        },

        closeApplication : function() {
            window.close();
        },

        loadHomeView : function() {
			yo.closeBubbleTooltip();
            Application.AppRouter.route(this.moduleKey, 'showHomeView' );
        },

        showHomeView : function() {
            $('.leftSection').addClass('hide-for-small-only');
            $('.rightSection').removeClass('show-for-medium-up');           
        },

        showMyAccountsView : function() {
            $('.leftSection').removeClass('hide-for-small-only');
            $('.rightSection').addClass('show-for-medium-up');
        }
    });
    return FLLayoutView;
});
define('10003600_js/controller/FLController',['10003600_js/views/FLLayoutView'], 
		function(FLLayoutView) {
		var FLController = Backbone.Marionette.Controller.extend({
		initialize: function(options) {
			Logger.debug('FLController is initialized.');
			this.regionCounter  = 0;
			// it is tempory fix for unblocking testing in QA
			var deviceInfo = Utilities.getDeviceInfo();
			if( deviceInfo.type == DESKTOP ) {
				$('html').css({
					'overflow-y' : 'auto'
				});
			}
  		},

		start: function(options) {
			this.mainRegion = options.region;
			this.flLayout = new FLLayoutView({ moduleKey : this.moduleKey });
			options.region.show(this.flLayout);
			yo.uiLoad.end();
		},

		showHomeView : function( options ) {
			if( !this.currentRegionId ) {
				this.currentRegionId = this.createNewRegion();	
			}
						
			var options = { regionId : 	this.currentRegionId };
			this.loadPopularSuggestedSitesModule( options )
		},

		loadPopularSuggestedSitesModule : function( options ) {
			this.loadSubModule('10003591', Utilities.getString('add_account'), options);
			$('.headerBtns').hide().removeClass('hide-for-small-only').removeClass('show-for-small-portrait')
				.removeClass('show-for-medium-portrait').removeClass('show-for-small-up');			
			$('#addAnotherAccBtn').addClass('hide');			
		},

		loadMyAccountsModule : function( options ) {
			var options = { regionId : 	'leftContent' };
			this.loadSubModule('10003595', '', options);
		},

		loadSiteLoginFormModule : function( options ) {
			this.loadSubModule('10003592', Utilities.getString('log_in'), options);
			$('.headerBtns').show().addClass('hide-for-small-only').addClass('show-for-small-portrait')
				.addClass('show-for-medium-portrait').addClass('show-for-small-up');
			$('#addAnotherAccBtn').removeClass('hide');
		},		

		loadSiteRefreshStatusModule : function( options ) {
			this.loadSubModule('10003593', Utilities.getString('security'), options);
		},

		loadAccountStatusModule : function( options ) {
			this.loadSubModule('10003594', Utilities.getString('add_account_status'), options);
			$('.headerBtns').show().removeClass('hide-for-small-only');
			$('#manageAccBtn').removeClass('hide');			
			$('#addAnotherAccBtn').removeClass('hide');
		},

		loadSubModule : function(moduleId, title, options) {
			Logger.debug('Sub Module Id : '+moduleId+' and options : '+JSON.stringify(options));
			var regionId = options.regionId;
			yo.inlineSpinner.show(regionId);
			Application.Appcore.loadModule({ 
					moduleKey : this.moduleKey, 
					moduleId : moduleId, 
					region : (options) ? this.flLayout.getRegion(regionId) : null, 
					data : options,
					callback : function(module) {
						yo.inlineSpinner.hide(Application.Appcore.getRegionId(module.moduleKey), true);
					}});
			if( title && title.length > 0 ) {
				$('.header .singleAccountHeaderTitle').html(title);
			}
		},

		createNewRegion : function() {

			var regionCount = this.regionCounter++;
			Logger.debug(this.mainRegion.el.id);
			var regionId = this.mainRegion.el.id+'_panel_'+regionCount;

			Logger.debug('Creating new region '+regionId);

			var element = jQuery('<div/>', {
			    id: regionId,
			    'class' : 'panel'
			}).prependTo(this.flLayout.rightContent.el);
			this.flLayout.addRegion( '#'+regionId, '#'+regionId );
			return '#'+regionId;
		}
	});
	return FLController;
});
define('10003600_js/finapp',['10003600_js/controller/FLController'], function(FLController) {
	var module = Application.Appcore.Module.extend({

		controller : FLController
		
	});
	return module;
});

