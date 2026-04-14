#include <iostream>
#include <sstream>
#include <iomanip>
#include <string>
#include <array>

#include <QDebug>
#include <QString>

#include "UdpPackageAnalyzer.h"

static constexpr int ethernetFramelength = 20;
static constexpr int ipv4HeaderLength = 14;
static constexpr int udpHeaderLength = 8;

static int currentPackageNumber = 0;

UdpPackageAnalyzer::UdpPackageAnalyzer(QObject *parent)
    : QObject(parent)
{
    ++currentPackageNumber;
    std::cout << "\nPackage creation for #" << currentPackageNumber << " requested....." << std::endl;
}

UdpPackageAnalyzer::~UdpPackageAnalyzer()
{
    std::cout << "\nPackage termination for #" << currentPackageNumber << " requested....." << std::endl;
    --currentPackageNumber;
}

UdpPackageAnalyzer::UdpPackageAnalyzer(char* ethernetPacket, int packetLength)
{
    setEthernetFrameHeader(ethernetPacket, packetLength);
    setIpv4Header(ethernetPacket);
    setIpv4HeaderChecksum(ethernetPacket);
    setSourceIPAdress(ethernetPacket);
    setDestinationIPAdress(ethernetPacket);
    setUdpHeader(ethernetPacket);
    setSourcePort(ethernetPacket);
    setDestinationPort(ethernetPacket);
    setUdpChecksum(ethernetPacket);
    setPayload(ethernetPacket, packetLength);
    setMainPacket(ethernetPacket, packetLength);
    setPacketLength(packetLength);
    setPayloadLength();
}

void UdpPackageAnalyzer::displayPackageDetails()
{
    qDebug() << "■ Ethernet frame header: " << m_ethernetFrameHeader <<
                "\n■ IPv4 header: " << m_ipv4Header <<
                "\n■ IPv4 header checksum: " << m_ipv4HeaderChecksum <<
                "\n■ Source IP Address: " << m_sourceIPAdress <<
                "\n■ Destination IP Address: " << m_destinationIPAdress <<
                "\n■ UDP header: " << m_udpHeader <<
                "\n■ Source port: " << m_sourcePort <<
                "\n■ Destination port: " << m_destinationPort <<
                "\n■ UDP Checksum: " << m_udpChecksum <<
                "\n■ UDP Payload: " << m_payload <<
                "\n■ UDP Payload size: " << m_payloadLength <<
                "\n■ UDP Main Packet: " << m_mainPacket <<
                "\n■ UDP Packet size: " << m_packetLength;
}

/*!
 * \brief Setter function for parsing the Ethernet Frame Header
 */
void UdpPackageAnalyzer::setEthernetFrameHeader(char* ethernetPacket, int packetLength)
{
    std::stringstream tempString;

    for (int i = 0; i < std::min(packetLength, ethernetFramelength); ++i) {
        tempString << ethernetPacket[i]; 
    }

    m_ethernetFrameHeader = QString::fromStdString(convertToHex(tempString.str(), 1));
    emit ethernetFrameHeaderChanged();
}

/*!
 * \brief Getter function for parsing the Ethernet Frame Header
 * \return Ethernet Frame Header content - 20 byte
 */
QString UdpPackageAnalyzer::getEthernetFrameHeader() const
{
    return m_ethernetFrameHeader;
}

/*!
 * \brief Setter function for parsing the IPv4 Header
 */
void UdpPackageAnalyzer::setIpv4Header(char* ethernetPacket)
{
    std::stringstream tempString;

    for (int i = ethernetFramelength; i < (ethernetFramelength + ipv4HeaderLength); ++i) {
        tempString << ethernetPacket[i]; 
    }

    m_ipv4Header = QString::fromStdString(convertToHex(tempString.str(), 1));
    emit ipv4HeaderChanged();
}

/*!
 * \brief Getter function for parsing the IPv4 Header
 * \return IPv4 Header content - 14 byte
 */
QString UdpPackageAnalyzer::getIpv4Header() const
{
    return m_ipv4Header;
}

/*!
 * \brief Setter function for parsing the IPv4 Header Checksum
 */
void UdpPackageAnalyzer::setIpv4HeaderChecksum(char* ethernetPacket)
{
    std::stringstream tempString;

    for (int i = ethernetFramelength; i < (ethernetFramelength + ipv4HeaderLength); ++i) {
        tempString << ethernetPacket[i]; 
    }

    m_ipv4HeaderChecksum = "0x" + QString::fromStdString(convertToHex(tempString.str().substr(4,2), 0));
    emit ipv4HeaderChecksumChanged();
}

/*!
 * \brief Getter function for parsing the IP checksum from IPv4 Header
 * \return IPv4 header checksum content - 2 byte
 */
QString UdpPackageAnalyzer::getIpv4HeaderChecksum() const
{
    return m_ipv4HeaderChecksum;
}

/*!
 * \brief Setter function for parsing the source IP Address
 */
void UdpPackageAnalyzer::setSourceIPAdress(char* ethernetPacket)
{
    std::string sourceIPAdressTemp;
    std::stringstream tempString;
    std::array <std::stringstream, 4> ssnetworkIDSources;
    std::array <unsigned int, 4> networkIDDecSources = {0};
    std::array <std::string, 4> networkIDComponents;

    for (int i = ethernetFramelength; i < (ethernetFramelength + ipv4HeaderLength); ++i) {
        tempString << ethernetPacket[i]; 
    }

    sourceIPAdressTemp = convertToHex(tempString.str().substr(6,4), 0);

    for (int i = 0; i <= 3; ++i) {
        networkIDComponents[i] = sourceIPAdressTemp.substr(i*2, 2);
        ssnetworkIDSources[i] << std::hex << networkIDComponents[i];
        ssnetworkIDSources [i] >> networkIDDecSources[i];
    }

    for (auto iter = networkIDDecSources.cbegin(); iter != networkIDDecSources.cend(); ++iter) {
        m_sourceIPAdress += QString::number(*iter) + (*iter == networkIDDecSources.back() ? "" : ".");
    }
    emit sourceIPAdressChanged();
}

/*!
 * \brief Getter function for parsing the Source IP Address
 * \return Source IP Address - 4 byte
 */
QString UdpPackageAnalyzer::getSourceIPAdress() const
{
    return m_sourceIPAdress;
}

/*!
 * \brief Setter function for parsing the destination IP Address
 */
void UdpPackageAnalyzer::setDestinationIPAdress(char* ethernetPacket)
{
    std::string destinationIPAdressTemp;
    std::stringstream tempString;
    std::array <std::stringstream, 4> ssnetworkIDDestinations;
    std::array <unsigned int, 4> networkIDDecDestinations = {0};
    std::array <std::string, 4> networkIDComponents;

    for (int i = ethernetFramelength; i < (ethernetFramelength + ipv4HeaderLength); ++i) {
        tempString << ethernetPacket[i]; 
    }

    destinationIPAdressTemp = convertToHex(tempString.str().substr(10,4), 0);

    for (int i = 0; i <= 3; ++i) {
        networkIDComponents[i] = destinationIPAdressTemp.substr(i*2, 2);
        ssnetworkIDDestinations[i] << std::hex << networkIDComponents[i];
        ssnetworkIDDestinations [i] >> networkIDDecDestinations[i];
    }

    for (auto iter = networkIDDecDestinations.cbegin(); iter != networkIDDecDestinations.cend(); ++iter) {
        m_destinationIPAdress += QString::number(*iter) + (*iter == networkIDDecDestinations.back() ? "" : ".");
    }
    emit destinationIPAdressChanged();
}

/*!
 * \brief Getter function for parsing the Destination IP Address
 * \return Destination IP Address - 4 byte
 */
QString UdpPackageAnalyzer::getDestinationIPAdress() const
{
    return m_destinationIPAdress;
}

/*!
 * \brief Setter function for parsing the UDP Header
 */
void UdpPackageAnalyzer::setUdpHeader(char* ethernetPacket)
{
    std::stringstream tempString;

    for (int i = (ethernetFramelength + ipv4HeaderLength); i < (ethernetFramelength + ipv4HeaderLength + udpHeaderLength); ++i) {
        tempString << ethernetPacket[i]; 
    }

    m_udpHeader = QString::fromStdString(convertToHex(tempString.str(), 1));
    emit udpHeaderChanged();
}

/*!
 * \brief Getter function for parsing the UDP Header frame
 * \return UDP Header frame content  - 8 byte
 */
QString UdpPackageAnalyzer::getUdpHeader() const
{
    return m_udpHeader;
}

/*!
 * \brief Setter function for parsing the source port
 */
void UdpPackageAnalyzer::setSourcePort(char* ethernetPacket)
{
    unsigned int sourcePortDec;
    std::string sourcePortTemp;
    std::stringstream tempString;

    for (int i = (ethernetFramelength + ipv4HeaderLength); i < (ethernetFramelength + ipv4HeaderLength + udpHeaderLength); ++i) {
        tempString << ethernetPacket[i]; 
    }

    sourcePortTemp = convertToHex(tempString.str().substr(0,2), 0);

    std::stringstream ssSourcePort;
    ssSourcePort << std::hex << sourcePortTemp;
    ssSourcePort >> sourcePortDec;

    m_sourcePort = QString::number(sourcePortDec);
    emit sourcePortChanged();
}

/*!
 * \brief Getter function for parsing the source port from UDP header
 * \return Source port content - 2 byte
 */
QString UdpPackageAnalyzer::getSourcePort() const
{
    return m_sourcePort;
}

/*!
 * \brief Setter function for parsing the destination port
 */
void UdpPackageAnalyzer::setDestinationPort(char* ethernetPacket)
{
    unsigned int destinationPortDec;
    std::string destinationPortTemp;
    std::stringstream tempString;

    for (int i = (ethernetFramelength + ipv4HeaderLength); i < (ethernetFramelength + ipv4HeaderLength + udpHeaderLength); ++i) {
        tempString << ethernetPacket[i]; 
    }

    destinationPortTemp = convertToHex(tempString.str().substr(2,2), 0);

    std::stringstream ssDestinationPort;
    ssDestinationPort << std::hex << destinationPortTemp;
    ssDestinationPort >> destinationPortDec;

    m_destinationPort =  QString::number(destinationPortDec);
    emit destinationPortChanged();
}

/*!
 * \brief Getter function for parsing the destination port from UDP header
 * \return Destination port content - 2 byte
 */
QString UdpPackageAnalyzer::getDestinationPort() const
{
    return m_destinationPort;
}

/*!
 * \brief Setter function for parsing the UDP Checksum
 */
void UdpPackageAnalyzer::setUdpChecksum(char* ethernetPacket)
{
    std::string udpChecksumTemp;
    std::stringstream tempString;

    for (int i = (ethernetFramelength + ipv4HeaderLength); i < (ethernetFramelength + ipv4HeaderLength + udpHeaderLength); ++i) {
        tempString << ethernetPacket[i]; 
    }

    udpChecksumTemp = convertToHex(tempString.str().substr(6,2), 0);

    m_udpChecksum = "0x" + QString::fromStdString(udpChecksumTemp);
    emit udpChecksumChanged();
}

/*!
 * \brief Getter function for parsing the UDP checksum from UDP header
 * \return UDP checksum content - 2 byte
 */
QString UdpPackageAnalyzer::getUdpChecksum() const
{
    return m_udpChecksum;
}

/*!
 * \brief Setter function for parsing the payload
 */
void UdpPackageAnalyzer::setPayload(char* ethernetPacket, int packetLength)
{
    std::stringstream tempString;

    for (int i = (ethernetFramelength + ipv4HeaderLength + udpHeaderLength); i < packetLength; ++i) {
        tempString << ethernetPacket[i]; 
    }

    m_payload = QString::fromStdString(convertToHex(tempString.str(), 1));
    emit payloadChanged();
}

/*!
 * \brief Getter function for parsing the Payload
 * \return Payload content
 */
QString UdpPackageAnalyzer::getPayload() const
{
    return m_payload;
}

/*!
 * \brief Setter function for parsing main the payload size
 */
void UdpPackageAnalyzer::setPayloadLength()
{
    m_payloadLength = m_packetLength - (ethernetFramelength + ipv4HeaderLength + udpHeaderLength);
    emit payloadLengthChanged();
}

/*!
 * \brief Getter function for parsing the payload length
 * \return Payload size
 */
int UdpPackageAnalyzer::getPayloadLength() const
{
    return m_payloadLength;
}

/*!
 * \brief Setter function for parsing the whole package at once
 */
void UdpPackageAnalyzer::setMainPacket(char* ethernetPacket, int packetLength)
{
    std::stringstream tempString;

    for (int i = 0; i < packetLength; ++i) {
        tempString << ethernetPacket[i];
    }

    m_mainPacket = QString::fromStdString(convertToHex(tempString.str(), 1));
}

/*!
 * \brief Getter function for parsing the whole UDP Packet
 * \return UDP Packet content
 */
QString UdpPackageAnalyzer::getMainPacket() const
{
    return m_mainPacket;
}

/*!
 * \brief Setter function for parsing main the packet size
 */
void UdpPackageAnalyzer::setPacketLength(int packetLength)
{
    m_packetLength = packetLength;
    emit packetLengthChanged(packetLength);
}

/*!
 * \brief Getter function for parsing the packet length
 * \return Main packet size
 */
int UdpPackageAnalyzer::getPacketLength() const
{
    return m_packetLength;
}

/*!
 * \brief String to Hex conversion operation
 * \param frameData - relevant part of the packet to be used for conversion
 * \param spaceSelection - selection option up to user for printing out -> 0: no space, 1: space
 * \return To-hex-converted value of the relevant frame
 */
std::string UdpPackageAnalyzer::convertToHex(const std::string &frameData, bool spaceSelection) {

    std::stringstream streamer;

    streamer << std::hex << std::setfill('0') << std::uppercase;
    for (size_t i = 0; frameData.length() > i; ++i) {
        streamer << std::setw(2) << static_cast<unsigned int>(static_cast<unsigned char>(frameData[i])) << (spaceSelection ? " " : "");
    }

    return streamer.str();
}