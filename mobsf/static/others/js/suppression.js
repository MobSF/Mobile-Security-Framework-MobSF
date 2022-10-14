
  $(document).ready(function () {
    if (window.location.hash == '#suppression') {
      $("#supbtn").click();
    }
  });



  //Suppression Logic
  
  function slugify(str)
  {
  return str
    .toLowerCase()
    .trim()
    .replace(/[^\w\s-]/g, '')
    .replace(/[\s_-]+/g, '-')
    .replace(/^-+|-+$/g, '');
  }
  
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

  function suppress(rule, files, tr, manifest=false){
    if (files){
      endpoint = suppress_by_files_url
      title = '<strong>Hide alert from files</strong>'
      html = `This will suppress any findings of the rule <b>${escapeHtml(rule)}</b> triggering from these files for <b>${escapeHtml(pkg)}</b> from now on.`
    } else {
      endpoint = suppress_by_rule_url
      title = '<strong>Disable Rule</strong>'
      html = `This will suppress the rule <b>${escapeHtml(rule)}</b> from tiggering for <b>${escapeHtml(pkg)}</b> from now on.`
    }
    if (manifest){
      table = '#table_manifest'
      type = 'manifest'
    } else {
      table = '#table_code'
      type = 'code'
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
        action(document.location.origin + endpoint,  { checksum: hash, rule, type }, function(json) {
            if (json.status==="ok") {
                $(table).DataTable().row(tr).remove().draw();
            } else {
              Swal.fire("Failed to Suppress")
            }
        });
      }
    });
      
  }

function remove_suppression(ctx){
  kind = $(ctx).data('kind');
  rule = $(ctx).data('rule');
  type = $(ctx).data('type');
  
  Swal.fire({
    title: 'Delete suppression rule?',
    type: 'warning',
    text: 'Do you want to delete the suppression rule?',
    showCancelButton: true,
    cancelButtonText: 'Cancel',
    confirmButtonText: 'Delete',
  }).then((result) => {
    if (result.value) {
      action(document.location.origin + delete_suppression_url, { checksum: hash, rule, kind, type }, function(json) {
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

function get_rules(type, rules){
  var html = ''
  rules.forEach(element => {
    html += `${escapeHtml(element)} - <a onclick='remove_suppression(this)' data-rule='${escapeHtml(element)}' data-type='${type}' data-kind='rule'><i class="fa fa-trash fa-2xs"></i></a></br>`
  });
  return html
}


function get_files(type, files){
  var html = ''
  for (const [rule, rfiles] of Object.entries(files)) {
    html += `<b>${escapeHtml(rule)}</b> - <a onclick='remove_suppression(this)' data-rule='${escapeHtml(rule)}' data-type='${type}' data-kind='file'><i class="fa fa-trash fa-2xs"></i></a></br>`
    html += `<a class="btn btn-primary btn-sm" data-toggle="collapse" href="#c_${slugify(escapeHtml(rule))}" role="button" aria-expanded="false" aria-controls="c_${slugify(escapeHtml(rule))}">Files ➜</a><div class="collapse" id="c_${slugify(escapeHtml(rule))}"><div class="card card-body">`
    rfiles.forEach(element => {
      html += `<li>${escapeHtml(element)}</li>`
    });
    html += '</div></div></br>'
  }
  return html
}

function list_suppressions(){
  $(document).ready(function () {
    action(document.location.origin + list_suppressions_url, { checksum: hash }, function(json) {
      if (json.status==="ok") {

        var tbl = $('#sup_table').DataTable();
        tbl.clear().draw();
          $(function() {
              $.each(json.message, function(i, item) {
                typ = item.SUPPRESS_TYPE
                rule_ids = get_rules(typ, item.SUPPRESS_RULE_ID)
                files = get_files(typ, item.SUPPRESS_FILES)
                tbl.row.add([typ, rule_ids, files]).draw(false)
              });
          });
      } else {
        Swal.fire("Failed to list Suppression rules")
      }
    });
  });
}