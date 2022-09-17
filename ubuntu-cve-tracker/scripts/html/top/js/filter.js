$(document).ready(function($) {
    fields_blacklist = ["Links", "Popularity", "Priority Score"];

    fields = get_filterable_fields($, fields_blacklist);
    configure_selector($('#field-selector'), fields, on_field_selector_change);

    //get_unique_column_values($, 5);

    $("#filter-button").click(handle_filter_button_click);
    $("#clear-filter-button").click(clear_filter);

    all_rows = $("#cves tbody").html().split("\n");
});

function get_filterable_fields($, fields_blacklist) {
    var fields = new Map();
    var index = 0;
    $("#cves tr th").each(function() {
        index++;
        var field = $(this).html().split(/<br>/)[0]
        if (fields_blacklist.includes(field)) {
            return;
        }
        fields.set(field, index);
    });

    return fields;
}

function configure_selector(field_selector, fields, on_change) {
    //field_selector_html = '<option value="unselected">-- Select an option --</option>'
    field_selector_html = ''
    for (const field of fields.keys()) {
        field_selector_html += '<option value="' + field + '">' + field + '</option>';
    }

    field_selector.html(field_selector_html);
    field_selector.change(on_change);
    field_selector.trigger("change");
}

function on_field_selector_change() {
    if (this.value.startsWith("Ubuntu") || this.value.includes("Status")) {
        $("#filter-criteria").html('<select id="filter-criteria-selector" class="form-control"></select>');
        var selector = $("#filter-criteria-selector");
        configure_selector(selector, get_unique_column_values($, fields.get(this.value)), nop);
    } else if (this.value == "Popularity" || this.value == "Priority Score") {
        // Skip for now
    } else {
        $("#filter-criteria").html('<input type="text" id="filter-criteria-regex" class="form-control"></input>');
        handle_filter_criteria_regex_enter_key();
    }
}

function get_unique_column_values($, column_number) {
    console.log("Getting unique for column " + column_number);
    var value_map = new Map();
    $("#cves tbody tr td:nth-child("+column_number+")").each(function() {
        value_map.set($(this).html(), true);
    });

    return value_map;
}

function handle_filter_button_click() {
    if ($('#filter-criteria-selector').length) {
        filter_by_selector($('#field-selector').val(), $('#filter-criteria-selector').val());
    } else if ($('#filter-criteria-regex').length) {
        filter_by_regex($('#field-selector').val(), $('#filter-criteria-regex').val());
    } else {
        console.log("Unable to process filter: Expected a selector or regex text field.");
    }
}

function filter_by_regex(column_name, filter_criteria) {
    var re = new RegExp(filter_criteria);
    displayed_rows = [];
    column_number = fields.get(column_name);
    console.log(column_name);
    console.log("#cves tbody tr td:nth-child("+column_number+")");
    $("#cves tbody tr td:nth-child("+column_number+")").each(function() {
        if (re.test($(this).html())) {
            displayed_rows.push($(this).parent()[0].outerHTML);
        }
    });

    display_rows(displayed_rows);
}

function filter_by_selector(column_name, filter_criteria) {
    displayed_rows = [];
    column_number = fields.get(column_name);
    console.log(column_name);
    console.log("#cves tbody tr td:nth-child("+column_number+")");
    $("#cves tbody tr td:nth-child("+column_number+")").each(function() {
        if ($(this).html() == filter_criteria) {
            displayed_rows.push($(this).parent()[0].outerHTML);
        }
    });

    display_rows(displayed_rows);
}

function nop() { }

function clear_filter() {
    display_rows(all_rows);
}

function display_rows(rows) {
    displayed_rows_html = "";
    rows.forEach(function(row) {
        displayed_rows_html += row + "\n";
    });

    $("#cves tbody").html(displayed_rows_html);
}

function handle_filter_criteria_regex_enter_key() {
    $('#filter-criteria-regex').keypress(function(e) {
        if (e.keyCode == 13) {
            $('#filter-button').click();
        }
    });
}


