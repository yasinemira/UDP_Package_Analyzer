import QtQuick 2.12
import QtQuick.Window 2.12
import QtQuick.Layouts 1.12

Window {
    visible: true
    width: 1280
    height: 900
    color: "#0b3945"
    title: qsTr("UDP Package Analyzer")

    QtObject {
        id: internal
        readonly property int rectWidth: 250
        readonly property int rectHeight: 50
        readonly property int rightMarginRect: 150
        readonly property int topMarginRect: 100
    }

    ColumnLayout {
        id: _udpPackageComponents
        width: 1075
        height: 740
        anchors.verticalCenterOffset: 0
        anchors.verticalCenter: parent.verticalCenter
        anchors.right: parent.right
        anchors.rightMargin: 100
        spacing: 5

        ComponentDetailGeneric {
            id: _ethernetFrameHeader
            dataContainerWidth: 450
            componentDefinition: "Ethernet Frame Header / 20-bytes"
            componentValue: udpInstance.ethernetFrameHeader
        }

        ComponentDetailGeneric {
            id: _ipv4Header
            dataContainerWidth: 340
            componentDefinition: "IPv4 Header / 14-bytes"
            componentValue: udpInstance.ipv4Header
        }

        ComponentDetailGeneric {
            id: _ipv4HeaderChecksum
            dataContainerWidth: 150
            componentDefinition: "IPv4 Header Checksum / 2-bytes"
            componentValue: udpInstance.ipv4HeaderChecksum
        }

        ComponentDetailGeneric {
            id: _sourceIPAdress
            dataContainerWidth: 150
            componentDefinition: "Source IP-Address / 2-bytes"
            componentValue: udpInstance.sourceIPAdress
        }

        ComponentDetailGeneric {
            id: _destinationIPAdress
            dataContainerWidth: 150
            componentDefinition: "Destination IP-Address / 4-bytes"
            componentValue: udpInstance.destinationIPAdress
        }

        ComponentDetailGeneric {
            id: _udpHeader
            dataContainerWidth: 200
            componentDefinition: "UDP Header / 8-bytes"
            componentValue: udpInstance.udpHeader
        }

        ComponentDetailGeneric {
            id: _sourcePort
            dataContainerWidth: 150
            componentDefinition: "Source Port / 2-bytes"
            componentValue: udpInstance.sourcePort
        }

        ComponentDetailGeneric {
            id: _destinationPort
            dataContainerWidth: 150
            componentDefinition: "Destination Port / 2-bytes"
            componentValue: udpInstance.destinationPort
        }

        ComponentDetailGeneric {
            id: _udpChecksum
            dataContainerWidth: 150
            componentDefinition: "UDP Checksum / 2-bytes"
            componentValue: udpInstance.udpChecksum
        }

        ComponentDetailGeneric {
            id: _payload
            dataContainerWidth: 600
            dataContainerHeight: 85
            height: 80
            componentDefinition: "Payload / " + udpInstance.payloadLength + "-bytes"
            componentValue: udpInstance.payload
        }
    }
}
