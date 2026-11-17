//Datatables
(function () {
  var base = document.currentScript ? document.currentScript.src : '';
  var pdfScripts = [
    new URL('../../datatables/js/pdfmake.min.js', base).href,
    new URL('../../datatables/js/vfs_fonts.js', base).href,
  ];
  var btnClass = 'btn-default btn-sm-menu btn-xs';

  // pdfmake is large and only needed for PDF export, so load it on click.
  var pdfButton = {
    text: '<i class="fa fa-file-pdf"></i>',
    titleAttr: 'PDF',
    className: btnClass,
    action: function (e, dt, node, config) {
      var button = this;
      mobsfLoadScripts(pdfScripts).then(function () {
        var pdf = $.fn.dataTable.ext.buttons.pdfHtml5;
        var conf = $.extend(true, {}, pdf, config, { title: '' });
        pdf.action.call(button, e, dt, node, conf);
      });
    },
  };

  // Defaults also apply to any later .DataTable() call on these pages.
  $.extend(true, $.fn.dataTable.defaults, {
    paging: true,
    lengthChange: false,
    searching: true,
    ordering: true,
    info: true,
    autoWidth: true,
    responsive: true,
    deferRender: true,
    dom: '<"top"<"left-col"><"center-col"Bl><"right-col"f>>rtip',
    buttons: [
      { extend: 'copy', text: '<i class="fa fa-copy"></i>', title: '', className: btnClass },
      { extend: 'csv', text: '<i class="fas fa-file-csv"></i>', title: '', className: btnClass },
      { extend: 'excel', text: '<i class="fa fa-file-excel"></i>', title: '', className: btnClass },
      pdfButton,
      { extend: 'print', text: '<i class="fa fa-print"></i>', title: '', className: btnClass },
    ],
  });

  // Initialize each table when it first becomes visible. Small tables
  // skip paging, search and the entry count.
  var SMALL_TABLE = 10;
  $(function () {
    $('table').each(function () {
      if (this.dataset.empty) {
        return;
      }
      mobsfWhenVisible(this, function (table) {
        if ($.fn.dataTable.isDataTable(table)) {
          return;
        }
        var large = mobsfRowCount(table) > SMALL_TABLE;
        // Tables with custom row filters need searching enabled at any size.
        var filtered = large || table.dataset.alwaysFilter === 'true';
        mobsfPrepareTable(table);
        $(table).DataTable({ paging: large, searching: filtered, info: large });
      });
    });
  });
})();
