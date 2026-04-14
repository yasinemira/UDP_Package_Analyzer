import QtQuick 2.0

/***
    \brief: A generic Rectangle component class to avoid content repetition for each instance
***/

Rectangle {
    id: root
    color: "#ffffff"
    radius: 20
    border.color: "gray"
    border.width: 2

    property string componentValue
    property alias dataHoveringBorderColor: root.border.color
    property alias dataHoveringBorderWidth: root.border.width

    Text {
        id: _udpPackageDetail
        anchors.fill: parent
        anchors.centerIn: parent
        text: root.componentValue
        wrapMode: Text.WordWrap
        verticalAlignment: Text.AlignVCenter
        horizontalAlignment: Text.AlignHCenter
        font.pixelSize: 13
        font.family: "Consolas"
    }
}
