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
        myalert("Started.");
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
	socket.on("run_resp", function(obj){
	    addPacket(obj);
	});
});
function myalert(v){
    $('#alertBar').text(new Date() + " "  + v);
}

function addPacketSimple(pak){
    $("#packetSimple").append("<tr  class='packet_simple_tr' onclick='showPacket(" + pak.num + ")'>" + "<td>" + pak.num + "</td>"+ "<td>" + pak.catch_time + "</td>"+ "<td>" + pak.final_protocol + "</td>"+ "</tr>");
}

function showPacket(pak_num){
    $(".packet_complex_tr").remove();
    var pak;
    for (var i = 0; i < packets.length;i++){
        if(packets[i].num == pak_num){
            pak = packets[i];
            break;
        }
    }
    if(pak != undefined){
        for (var property in pak) {
            if(pak.hasOwnProperty(property)) {
                $("#packetComplex").append("<tr class='packet_complex_tr'>" + "<td>" + property + "</td>"+ "<td>" + pak[property] + "</td>" + "</tr>");
             }
        }
    }
}
function addPacket(pak){
        if(packets.length>=100){
            $(".packet_simple_tr")[0].remove();
            packets.shift();
        }
        addPacketSimple(pak);
        packets.push(pak);
};