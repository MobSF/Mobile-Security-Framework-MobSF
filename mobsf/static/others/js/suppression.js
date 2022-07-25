
  $(document).ready(function () {
    if (window.location.hash == '#suppression') {
      $("#supbtn").click();
    }
  });

  //Suppression Logic
  function escapeHtml(unsafe)
  {
    return unsafe
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
  }

  function action(url, data, on_success){
    //Add CSRF
    data.csrfmiddlewaretoken = csrf;
    $.ajax({
      url : url, 
      type : "POST",
      dataType: "json", 
      data : data,
      success : function(json){ on_success(json) },
      error : function(xhr, ajaxOptions, thrownError) {
        console.log(xhr.responseText);
      }
    });
  }

  function suppress(rule, files, tr){
    if (files){
      endpoint = '/suppress_by_files/'
      title = '<strong>Hide alert from files</strong>'
      html = `This will suppress any findings of the rule <b>${escapeHtml(rule)}</b> triggering from these files for <b>${escapeHtml(pkg)}</b> from now on.`
    } else {
      endpoint = '/suppress_by_rule/'
      title = '<strong>Disable Rule</strong>'
      html = `This will suppress the rule <b>${escapeHtml(rule)}</b> from tiggering for <b>${escapeHtml(pkg)}</b> from now on.`
    }

    Swal.fire({
      title: title,
      type: 'warning',
      html: html,
      showCancelButton: true,
      cancelButtonText: 'Cancel',
      confirmButtonText: 'Suppress',
    }).then((result) => {
      if (result.value) {
        action(document.location.origin + endpoint, { checksum: hash, rule }, function(json) {
            if (json.status==="ok") {
                $('#table_code').DataTable().row(tr).remove().draw();
            } else {
              Swal.fire("Failed to Suppress")
            }
        });
      }
    });
      
  }

function remove_suppression(ctx){
  type = $(ctx).data('type');
  rule = $(ctx).data('rule');
  
  Swal.fire({
    title: 'Delete suppression rule?',
    type: 'warning',
    text: 'Do you want to delete the suppression rule?',
    showCancelButton: true,
    cancelButtonText: 'Cancel',
    confirmButtonText: 'Delete',
  }).then((result) => {
    if (result.value) {
      action(document.location.origin + '/delete_suppression/', { checksum: hash, rule, type }, function(json) {
          if (json.status==="ok") {
            window.location.hash = 'suppression';
            window.location.reload();
          } else {
            Swal.fire("Failed to remove suppression rule")
          }
      });
    }
  });

}

function get_rules(rules){
  var html = ''
  rules.forEach(element => {
    html += `${escapeHtml(element)} - <a onclick='remove_suppression(this)' data-rule='${escapeHtml(element)}' data-type='rule'><i class="fa fa-trash fa-2xs"></i></a></br>`
  });
  return html
}


function get_files(files){
  var html = ''
  for (const [rule, rfiles] of Object.entries(files)) {
    html += `<b>${escapeHtml(rule)}</b> - <a onclick='remove_suppression(this)' data-rule='${escapeHtml(rule)}' data-type='file'><i class="fa fa-trash fa-2xs"></i></a></br>`
    rfiles.forEach(element => {
      html += `<li>${escapeHtml(element)}</li>`
    });
    html += '</br>'
  }
  return html
}

function list_suppressions(){
  action(document.location.origin + '/list_suppressions/', { checksum: hash }, function(json) {
    if (json.status==="ok") {

       var tbl = $('#sup_table').DataTable();
       tbl.clear().draw();
        $(function() {
            $.each(json.message, function(i, item) {
              typ = item.SUPPRESS_TYPE
              rule_ids = get_rules(item.SUPPRESS_RULE_ID)
              files = get_files(item.SUPPRESS_FILES)
              tbl.row.add([typ, rule_ids, files]).draw(false)
            });
        });
    } else {
      Swal.fire("Failed to list Suppression rules")
    }
  });
}