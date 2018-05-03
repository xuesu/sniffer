var socket;
var packets = [];
$(document).ready(function(){
    socket = io.connect('http://' + document.domain + ':' + location.port);
    $('#protocolCheckBtn').on('click', function() {
        var protos = [];
        $.each($(".protocolCheckboxes"), function(index, item){
            if($(item).prop("checked"))protos.push(item.value);
        });
        socket.emit("set_protos_req", protos);
    });
    $('#RunStartBtn').on('click', function() {
        socket.emit("run_req");
    });
    $('#RunStopBtn').on('click', function() {
        socket.emit("stop_req");
    });
    $('.addrTypeLi').on('click', function() {
       $("#addrType").text($(this).text());
    });
    $('.addrFromLi').on('click', function() {
       $("#addrFrom").text($(this).text());
    });
	socket.on('set_device_resp', function(msg) {
        $('#deviceName').text(msg);
	});
	socket.on('set_protos_resp', function(msg) {
        $('#filtersName').val(msg);
	});
	socket.on("error", function(e){
        myalert(e.type + ":" + e.message);
	});
	socket.on("stop_resp", function(e){
        myalert("Stopped.");
	});
	socket.on("start_resp", function(e){
        myalert("Started.");
	});
	socket.on("run_resp", function(obj){
	    addPacket(obj);
	});
	socket.on("add_addr_filter_resp", function(obj){
	    showExistedFilter(obj);
	});
	socket.on("remove_addr_filter_resp", function(obj){
	    showExistedFilter(obj);
	});
});
function myalert(v){
    $('#alertBar').text(new Date() + " "  + v);
}

function addPacketSimple(pak){
    $("#packetSimple").append("<tr  class='packet_simple_tr' onclick='showPacket(" + pak['BASIC'].num + ")'>" + "<td>" + pak['BASIC'].num + "</td>"+ "<td>" + pak['BASIC'].catch_time + "</td>"+ "<td>" + pak['BASIC'].final_protocol + "</td>"+ "</tr>");
}

function showPacket(pak_num){
    $(".packet_complex_panel").remove();
    var pak;
    for (var i = 0; i < packets.length;i++){
        if(packets[i]['BASIC'].num == pak_num){
            pak = packets[i];
            break;
        }
    }
    if(pak != undefined){
        var protos = Object.keys(pak);
        protos.sort();
        for (var i in protos){
            var protocol_name = protos[i];
            var table_content = ""
            var properties = Object.keys(pak[protocol_name]);
            properties.sort();
            for (var j in  properties){
                var property = properties[j];
                 table_content += "<tr>" + "<td>" + property + "</td>"+ "<td>" + pak[protocol_name][property] + "</td>" + "</tr>";
            }
            $("#packetComplex").append("<div class='panel panel-default packet_complex_panel'><div class='panel-heading'><h4 class='panel-title'><a data-target='#collapse" + protocol_name + "' href='#collapse" + protocol_name + "' data-toggle='gsdk-collapse'>" + protocol_name + "</a></h4></div><div id='collapse" + protocol_name + "' class='panel-collapse collapse'><div class='panel-body'><table class='packet_table'><thead><tr><th>Name</th><th>Value</th></tr></thead><tbody>" + table_content + "</tbody></table></div></div></div>");
        }
    }
    init_gsdk_collapse();
}
function addPacket(pak){
        if(packets.length>=100){
            $(".packet_simple_tr")[0].remove();
            packets.shift();
        }
        addPacketSimple(pak);
        packets.push(pak);
};

function showExistedFilter(filters_strs){
    var listStr = "";
    for(var i = 0;i < filters_strs.length;i++){
        listStr += "<li>" + filters_strs[i] + "<a href='#' onclick='socket.emit(\"remove_addr_filter_req\", " + i + ")'>X</a></li>";
    }
    $("#addedAddrFilters").empty();
    $("#addedAddrFilters").append(listStr);
}

function addAddrFilter() {
    var from_s = $("#addrFrom").text();
    var type_s = $("#addrType").text();
    var addr = $("#filterNewAddr").val();
    socket.emit("add_addr_filter_req", from_s, type_s, addr);
}