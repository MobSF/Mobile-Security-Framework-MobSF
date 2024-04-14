//Datatables
$(function () {
    // Datatable
    $('table').DataTable({
      "paging": true,
      "lengthChange": false,
      "searching": true,
      "ordering": true,
      "info": true,
      "autoWidth": true,
      "responsive": true,
      "dom": '<"top"<"left-col"><"center-col"Bl><"right-col"f>>rtip',
      "buttons": [
        {
            extend: 'copy',
            text: '<i class="fa fa-copy"></i>',
            title: '',
            className: 'btn-default btn-sm-menu btn-xs',
        },
        {
            extend: 'csv',
            text:      '<i class="fas fa-file-csv"></i>',
            title: '',
            className: 'btn-default btn-sm-menu btn-xs',
        },
        {
            extend: 'excel',
            text:      '<i class="fa fa-file-excel"></i>',
            title: '',
            className: 'btn-default btn-sm-menu btn-xs',
        },
        {
            extend: 'pdf',
            text:      '<i class="fa fa-file-pdf"></i>',
            title: '',
            className: 'btn-default btn-sm-menu btn-xs',
        },
        {
            extend: 'print',
            text:      '<i class="fa fa-print"></i>',
            title: '',
            className: 'btn-default btn-sm-menu btn-xs',
        },
      ],
    });
  });