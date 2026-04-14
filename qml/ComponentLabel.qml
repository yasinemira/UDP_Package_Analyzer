import QtQuick 2.0

Item {
    id: root
    width: 350
    height: 40

    property var componentDefinition
    property alias labelHoveringColor: _componentLabel.color

    Text {
        id: _componentLabel
        text: "■ " + root.componentDefinition
        color: "gray"
        wrapMode: Text.WordWrap
        verticalAlignment: Text.AlignVCenter
        horizontalAlignment: Text.AlignHCenter
        font.pixelSize: 22
        font.family: "Consolas"
    }
}
