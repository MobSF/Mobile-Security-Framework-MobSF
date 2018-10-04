'use strict';

/*

Main javascript functions to init most of the elements

#1. RANGE SLIDER
#2. FEATURES SELECT
#3. STAR RATING
#4. DATE RANGE PICKER
#5. FILTER TOGGLER
#6. FILTERS PANEL MAIN TOGGLER

*/

$(function () {

  // #1. RANGE SLIDER
  if ($('.ion-range-slider').length) {
    $('.ion-range-slider').ionRangeSlider({
      type: "double",
      min: 0,
      max: 1000000,
      from: 200000,
      to: 800000,
      prefix: "$",
      step: 50000
    });
  }

  // #2. FEATURES SELECT


  if ($('.select2').length) {
    $('.select2').select2();
  }

  // #3. STAR RATING

  $('.item-star-rating').barrating({ theme: 'osadmin', readonly: true });

  // #4. DATE RANGE PICKER
  var rental_start = moment();
  var rental_end = moment().add(14, 'days');
  $('.date-range-picker').daterangepicker({
    startDate: rental_start,
    endDate: rental_end,
    locale: {
      format: 'MMM D, YYYY'
    }
  });

  // #5. FILTER TOGGLER

  $('.filter-toggle').on('click', function () {
    var $filter_w = $(this).closest('.filter-w');
    if ($filter_w.hasClass('collapsed')) {
      $filter_w.find('.filter-body').slideDown(300, function () {
        $filter_w.removeClass('collapsed');
      });
    } else {
      $filter_w.find('.filter-body').slideUp(300, function () {
        $filter_w.addClass('collapsed');
      });
    }
    return false;
  });

  // #6. FILTERS PANEL MAIN TOGGLER

  $('.filters-toggler').on('click', function () {
    $('.rentals-list-w').toggleClass('hide-filters');
    return false;
  });
});
