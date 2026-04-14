import QtQuick 2.0

Item {
    id: root
    width: parent.width
    height: 70
    anchors.right: parent.right
    anchors.rightMargin: 20

    property var componentDefinition
    property string componentValue
    property int dataContainerWidth
    property int dataContainerHeight: 50

    QtObject {
        id: internal

        property var hoveringColor: "#a9d5e3"
    }

    ComponentLabel {
        id: _componentLabel
        height: 40
        anchors.verticalCenter: parent.verticalCenter
        anchors.left: parent.left
        anchors.leftMargin: 50
        componentDefinition: root.componentDefinition
    }

    DataContainer {
        id: _dataContainer
        width: root.dataContainerWidth
        height: root.dataContainerHeight
        componentValue: root.componentValue
        anchors.right: parent.right
        anchors.rightMargin: 20
    }

    MouseArea {
        id: _hoveringArea
        anchors.fill: parent
        hoverEnabled: true
        onContainsMouseChanged: {
            if (containsMouse) {
                _componentLabel.labelHoveringColor = internal.hoveringColor
                _dataContainer.dataHoveringBorderColor = internal.hoveringColor
                _dataContainer.dataHoveringBorderWidth = 5
            } else {
                _componentLabel.labelHoveringColor = "gray"
                _dataContainer.border.color = "gray"
                _dataContainer.dataHoveringBorderWidth = 2
            }
        }
    }
}
