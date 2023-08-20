package org.foo.app;

import org.onosproject.cfg.ComponentConfigService;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Dictionary;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

import static org.onlab.util.Tools.get;

// Edited code imported packages
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.device.DeviceService;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Iterator;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.criteria.Criterion;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.IpAddress;
import org.onosproject.net.flow.FlowEntry;
import org.onlab.packet.Ip4Address;

import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.Criterion.Type;
import org.onosproject.net.flow.criteria.IPCriterion;
import org.onosproject.net.flow.criteria.IPProtocolCriterion;

import org.onosproject.net.flow.FlowEntry.FlowEntryState;
import org.onosproject.net.flow.FlowRule;

import org.onosproject.net.flow.criteria.TcpPortCriterion;
import org.onosproject.net.flow.criteria.UdpPortCriterion;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;

import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true, service = { SomeInterface.class }, property = {
        "someProperty=Some Default String Value",
})
public class AppComponent implements SomeInterface {

    private final Logger log = LoggerFactory.getLogger(getClass());
    private final String LOG_FILE_PATH = "./file.txt";
    String desktopPath = "/home/wifi/Desktop";
    String csvFilePath = desktopPath + File.separator + "flow_data.csv";

    /** Some configurable property. */
    private String someProperty;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    // Edited code
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;

    private volatile boolean running;
    private volatile int newEntriesCount;
    private Set<String> uniqueConnections = new HashSet<>();
    private long totalDuration; // Total duration of all connections
    private int totalConnections; // Total number of connections

    private Set<IpAddress> sourceIpAddressesA = new HashSet<>();
    private Set<IpAddress> sourceIpAddressesB = new HashSet<>();
    private Set<IpAddress> sourceIpAddressesC = new HashSet<>();
    private Set<IpAddress> sourceIpAddressesOther = new HashSet<>();

    private Set<IpAddress> destinationIpAddressesA = new HashSet<>();
    private Set<IpAddress> destinationIpAddressesB = new HashSet<>();
    private Set<IpAddress> destinationIpAddressesC = new HashSet<>();
    private Set<IpAddress> destinationIpAddressesOther = new HashSet<>();

    private int sourcePortsBelow1024Count = 0;
    private int sourcePortsAbove1024Count = 0;

    private int destinationPortsBelow1024Count = 0;
    private int destinationPortsAbove1024Count = 0;

    private int tcpProtocolCount = 0;
    private int udpProtocolCount = 0;
    private int icmpProtocolCount = 0;
    private int otherProtocolCount = 0;

    private Map<String, Integer> packetCounts = new HashMap<>();

    private double calculateEntropy(Map<String, Integer> packetCounts) {
        int totalPackets = 0;
        for (int count : packetCounts.values()) {
            totalPackets += count;
        }

        double entropy = 0.0;
        if (totalPackets != 0) {
            for (int count : packetCounts.values()) {
                double probability = (double) count / totalPackets;
                entropy -= probability * (Math.log(probability) / Math.log(2));
            }
        }
        return entropy;
    }

    private Map<IpAddress, Long> sourceIpBytes = new HashMap<>();
    private Map<String, Long> flowDurations = new HashMap<>();
    private double entropyOfSourceIpBytes;

    private double calculateEntropyByte(Map<IpAddress, Long> sourceIpBytes) {
        long totalBytes = 0;
        for (long bytes : sourceIpBytes.values()) {
            totalBytes += bytes;
        }

        double entropy = 0.0;
        if (totalBytes != 0) {
            for (long bytes : sourceIpBytes.values()) {
                double probability = (double) bytes / totalBytes;
                entropy -= probability * (Math.log(probability) / Math.log(2));
            }
        }
        return entropy;
    }

    private void updateSourceIpBytes(IpAddress sourceIp, long bytes) {
        if (sourceIpBytes.containsKey(sourceIp)) {
            sourceIpBytes.put(sourceIp, sourceIpBytes.get(sourceIp) + bytes);
        } else {
            sourceIpBytes.put(sourceIp, bytes);
        }
    }

    private void writeNumberOfConnectionsToFile(int numberOfConnections, int normalConnectionsCount,
            int backgroundConnectionsCount, long meanDuration, int sourceIpAddressesACount,
            int sourceIpAddressesBCount, int sourceIpAddressesCCount, int sourceIpAddressesOtherCount,
            int destinationIpAddressesACount, int destinationIpAddressesBCount,
            int destinationIpAddressesCCount, int destinationIpAddressesOtherCount,
            int sourcePortsBelow1024Count, int sourcePortsAbove1024Count,
            int destinationPortsBelow1024Count, int destinationPortsAbove1024Count,
            int tcpProtocolCount, int udpProtocolCount, int icmpProtocolCount, int otherProtocolCount,
            double packetsTransferredEntropy, double entropyOfSourceIpBytes) {
        try (PrintWriter writer = new PrintWriter(new FileWriter("/home/wifi/Desktop/new_features.csv", true))) {
            // writer.println(
            // "Number of Unique Connections,Number of Normal Connections,Number of
            // Background Connections");
            writer.println(numberOfConnections + "," + normalConnectionsCount + "," + backgroundConnectionsCount + ","
                    + meanDuration + "," + sourceIpAddressesACount + "," + sourceIpAddressesBCount + ","
                    + sourceIpAddressesCCount + "," + sourceIpAddressesOtherCount + "," + destinationIpAddressesACount
                    + "," + destinationIpAddressesBCount + "," + destinationIpAddressesCCount + ","
                    + destinationIpAddressesOtherCount + "," + sourcePortsBelow1024Count + ","
                    + sourcePortsAbove1024Count + "," + destinationPortsBelow1024Count + ","
                    + destinationPortsAbove1024Count + "," + tcpProtocolCount + "," + udpProtocolCount + ","
                    + icmpProtocolCount + "," + otherProtocolCount + "," + packetsTransferredEntropy + ","
                    + entropyOfSourceIpBytes);

            log.info("Connections data appended to new_features.csv");
        } catch (IOException e) {
            log.error("Error writing connections data to new_features.csv file", e);
        }
    }

    @Activate
    protected void activate() {
        cfgService.registerProperties(getClass());
        log.info("Started");
        running = true;

        File newFeaturesFile = new File("/home/wifi/Desktop/new_features.csv");
        try {
            newFeaturesFile.createNewFile();
        } catch (IOException e) {
            log.error("Error creating new_features.csv file", e);
        }
    }

    @Deactivate
    protected void deactivate() {
        cfgService.unregisterProperties(getClass(), false);
        log.info("Stopped");
        running = false;
    }

    @Modified
    public void modified(ComponentContext context) {
        // int newEntriesCount = 0;
        Dictionary<?, ?> properties = context != null ? context.getProperties() : new Properties();
        if (context != null) {
            someProperty = get(properties, "someProperty");
        }
        log.info("Reconfigured");
        // edited code starts here

        int packetCount = 0;

        long byteCount = 0;
        int normalConnectionsCount = 0;
        int backgroundConnectionsCount = 0;

        while (running) {
            try {
                newEntriesCount = 0;

                // Get all devices
                Iterable<Device> devices = deviceService.getDevices();

                packetCount = 0;

                // Reset byte count for each device
                byteCount = 0;

                try (PrintWriter writer = new PrintWriter(new FileWriter(csvFilePath, true))) {

                    // int newEntriesCount = 0;
                    for (Device device : devices) {
                        // Retrieve flow entries for the device
                        Iterable<FlowEntry> flowEntries = flowRuleService.getFlowEntries(device.id());

                        for (FlowEntry flowEntry : flowEntries) {

                            

                            // Extract flow state flags
                            FlowEntryState flowState = flowEntry.state();

                            // Extract flow data from flow entry
                            String flowId = flowEntry.id().toString();
                            String deviceId = flowEntry.deviceId().toString();

                            // Accumulate byte count for each flow entry
                            byteCount += flowEntry.bytes();

                            // Extract source IP address
                            IpAddress srcIpAddress = null;
                            Criterion srcIpCriterion = flowEntry.selector().getCriterion(Type.IPV4_SRC);
                            if (srcIpCriterion instanceof IPCriterion) {
                                IpPrefix srcIpPrefix = ((IPCriterion) srcIpCriterion).ip();
                                if (srcIpPrefix.isIp4()) {
                                    srcIpAddress = srcIpPrefix.address().getIp4Address();
                                }
                            }

                            // Update byte count for the source IP
                            if (srcIpAddress != null) {
                                updateSourceIpBytes(srcIpAddress, flowEntry.bytes());
                            }

                            // Check the source IP address class
                            if (srcIpAddress != null) {
                                byte[] addressBytes = srcIpAddress.toOctets();
                                if ((addressBytes[0] & 0xFF) == 10) {
                                    sourceIpAddressesA.add(srcIpAddress);
                                } else if ((addressBytes[0] & 0xF0) == 0x40) {
                                    sourceIpAddressesB.add(srcIpAddress);
                                } else if ((addressBytes[0] & 0xF0) == 0x80) {
                                    sourceIpAddressesC.add(srcIpAddress);
                                } else {
                                    sourceIpAddressesOther.add(srcIpAddress);
                                }
                            }

                            // Extract destination IP address
                            Ip4Address dstIpAddress = null;
                            Criterion dstIpCriterion = flowEntry.selector().getCriterion(Type.IPV4_DST);
                            if (dstIpCriterion instanceof IPCriterion) {
                                IpPrefix dstIpPrefix = ((IPCriterion) dstIpCriterion).ip();
                                if (dstIpPrefix.isIp4()) {
                                    dstIpAddress = dstIpPrefix.address().getIp4Address();
                                }
                            }

                            if (dstIpAddress != null) {
                                byte[] addressBytes = dstIpAddress.toOctets();
                                if ((addressBytes[0] & 0xFF) == 10) {
                                    destinationIpAddressesA.add(dstIpAddress);
                                } else if ((addressBytes[0] & 0xF0) == 0x40) {
                                    destinationIpAddressesB.add(dstIpAddress);
                                } else if ((addressBytes[0] & 0xF0) == 0x80) {
                                    destinationIpAddressesC.add(dstIpAddress);
                                } else {
                                    destinationIpAddressesOther.add(dstIpAddress);
                                }
                            }

                            // Extract source port number
                            int srcPortNumber = 0;
                            Criterion srcPortCriterion = flowEntry.selector().getCriterion(Type.TCP_SRC);
                            if (srcPortCriterion != null && srcPortCriterion instanceof TcpPortCriterion) {
                                srcPortNumber = ((TcpPortCriterion) srcPortCriterion).tcpPort().toInt();
                            } else {
                                srcPortCriterion = flowEntry.selector().getCriterion(Type.UDP_SRC);
                                if (srcPortCriterion != null && srcPortCriterion instanceof UdpPortCriterion) {
                                    srcPortNumber = ((UdpPortCriterion) srcPortCriterion).udpPort().toInt();
                                }
                            }

                            // Check the source port and increment the corresponding counters
                            if (srcPortNumber < 1024) {
                                sourcePortsBelow1024Count++;
                            } else {
                                sourcePortsAbove1024Count++;
                            }

                            // Extract destination port number
                            int dstPortNumber = 0;
                            Criterion dstPortCriterion = flowEntry.selector().getCriterion(Type.TCP_DST);
                            if (dstPortCriterion != null && dstPortCriterion instanceof TcpPortCriterion) {
                                dstPortNumber = ((TcpPortCriterion) dstPortCriterion).tcpPort().toInt();
                            } else {
                                dstPortCriterion = flowEntry.selector().getCriterion(Type.UDP_DST);
                                if (dstPortCriterion != null && dstPortCriterion instanceof UdpPortCriterion) {
                                    dstPortNumber = ((UdpPortCriterion) dstPortCriterion).udpPort().toInt();
                                }
                            }

                            // Check the destination port and increment the corresponding counters
                            if (dstPortNumber < 1024) {
                                destinationPortsBelow1024Count++;
                            } else {
                                destinationPortsAbove1024Count++;
                            }

                            // Extract protocol type
                            String protocolTypeText;
                            Criterion protocolCriterion = flowEntry.selector().getCriterion(Type.IP_PROTO);
                            byte protocolType = (protocolCriterion instanceof IPProtocolCriterion)
                                    ? (byte) ((IPProtocolCriterion) protocolCriterion).protocol()
                                    : -1;

                            switch (protocolType) {
                                case 1:
                                    protocolTypeText = "ICMP";
                                    icmpProtocolCount++;
                                    break;
                                case 6:
                                    protocolTypeText = "TCP";
                                    tcpProtocolCount++;
                                    break;
                                case 17:
                                    protocolTypeText = "UDP";
                                    udpProtocolCount++;
                                    break;
                                default:
                                    protocolTypeText = "Unknown";
                                    otherProtocolCount++;
                                    break;
                            }

                            // Increment packet count for each flow entry
                            packetCount += flowEntry.packets();

                            // Accumulate byte count for each flow entry
                            byteCount += flowEntry.bytes();

                            String connection = srcIpAddress + ":" + srcPortNumber + "-" + dstIpAddress + ":"
                                    + dstPortNumber + "-" + protocolTypeText;
                            uniqueConnections.add(connection);

                            if (protocolType == 6) { // TCP protocol
                                if (srcPortNumber >= 1024 && srcPortNumber <= 49151 &&
                                        dstPortNumber >= 1024 && dstPortNumber <= 49151) {
                                    normalConnectionsCount++;
                                }
                            }

                            // Increment backgroundConnectionsCount if the flow entry represents a
                            // background connection
                            if (protocolType == 17) { // UDP protocol
                                if (srcPortNumber >= 49152 && srcPortNumber <= 65535 &&
                                        dstPortNumber >= 49152 && dstPortNumber <= 65535) {
                                    backgroundConnectionsCount++;
                                }
                            }

                            long durationMillis = flowEntry.life();
                            totalDuration += durationMillis;
                            totalConnections++;

                            flowDurations.put(flowId, durationMillis);

                            // Log the extracted information
                            String logMessage = String.format(
                                    "Flow Entry: flowId=%s, deviceId=%s, srcIp=%s, srcPort=%d, dstIp=%s, dstPort=%d, protocol=%s, packets=%d, bytes=%d, state=%s",
                                    flowEntry.id(), flowEntry.deviceId(), srcIpAddress, srcPortNumber, dstIpAddress,
                                    dstPortNumber,
                                    protocolTypeText, flowEntry.packets(), flowEntry.bytes(), flowState);

                            log.info(logMessage);
                            writer.println(logMessage);

                            writer.println(
                                    flowEntry.id() + "," + flowEntry.deviceId() + "," + protocolType + ","
                                            + srcIpAddress + ","
                                            + srcPortNumber + "," + dstIpAddress + "," + dstPortNumber + ","
                                            + flowEntry.packets() + ","
                                            + flowEntry.bytes() + "," + flowState);

                            writer.flush();
                            System.out.println("Data written to CSV file: " + csvFilePath);

                            newEntriesCount++;

                        }

                        try (PrintWriter durationWriter = new PrintWriter(new FileWriter("/home/wifi/Desktop/new_features.csv"))) {
                            durationWriter.println("Flow ID,Duration (ms)");
                        
                            for (Map.Entry<String, Long> entry : flowDurations.entrySet()) {
                                durationWriter.println(entry.getKey() + "," + entry.getValue());
                            }
                        
                            log.info("Flow durations written to flow_durations.csv");
                        } catch (IOException e) {
                            log.error("Error writing flow durations to flow_durations.csv file", e);
                        

                        // Store packet count in a map for calculating entropy
                        packetCounts.put(device.id().toString(), packetCount);
                        }
                    }
                    int numberOfConnections = uniqueConnections.size();
                    log.info("Number of unique connections: {}", numberOfConnections);

                    long meanDuration = totalConnections > 0 ? totalDuration / totalConnections : 0;

                    // Log the mean duration
                    log.info("Mean Duration of all connections: {} ms", meanDuration);

                    // Calculate counts of source IP addresses for each class
                    int sourceIpAddressesACount = sourceIpAddressesA.size();
                    int sourceIpAddressesBCount = sourceIpAddressesB.size();
                    int sourceIpAddressesCCount = sourceIpAddressesC.size();
                    int sourceIpAddressesOtherCount = sourceIpAddressesOther.size();

                    log.info("Source IP Addresses (A class) Count: {}", sourceIpAddressesACount);
                    log.info("Source IP Addresses (B class) Count: {}", sourceIpAddressesBCount);
                    log.info("Source IP Addresses (C class) Count: {}", sourceIpAddressesCCount);
                    log.info("Source IP Addresses (Other class) Count: {}", sourceIpAddressesOtherCount);

                    // Calculate counts of destination IP addresses for each class
                    int destinationIpAddressesACount = destinationIpAddressesA.size();
                    int destinationIpAddressesBCount = destinationIpAddressesB.size();
                    int destinationIpAddressesCCount = destinationIpAddressesC.size();
                    int destinationIpAddressesOtherCount = destinationIpAddressesOther.size();

                    log.info("Destination IP Addresses (A class) Count: {}", destinationIpAddressesACount);
                    log.info("Destination IP Addresses (B class) Count: {}", destinationIpAddressesBCount);
                    log.info("Destination IP Addresses (C class) Count: {}", destinationIpAddressesCCount);
                    log.info("Destination IP Addresses (Other class) Count: {}", destinationIpAddressesOtherCount);

                    log.info("tcp protocol Count: {}", tcpProtocolCount);
                    log.info("udp protocol Count: {}", udpProtocolCount);
                    log.info("icmp protocol Count: {}", icmpProtocolCount);
                    log.info("other protocol Count: {}", otherProtocolCount);

                    double packetsTransferredEntropy = calculateEntropy(packetCounts);

                    log.info("packets Transferred Entropy: {}", packetsTransferredEntropy);

                    // Calculate entropy of bytes transferred from source IP addresses
                    entropyOfSourceIpBytes = calculateEntropyByte(sourceIpBytes);

                    log.info("Bytes of Source Entropy: {}", entropyOfSourceIpBytes);

                    uniqueConnections.clear();
                    log.info("Flow data logged successfully in the file: {}", csvFilePath);
                    log.info("New flow entries count: {}", newEntriesCount);
                    newEntriesCount = 0;
                } catch (IOException e) {
                    log.error("Error writing flow data to the log file: {}", csvFilePath, e);
                }

                // edited code ends here
                log.info("Task Completed");
                Thread.sleep(30000); // 10-second delay
            } catch (InterruptedException e) {
                log.error("Flow data collection interrupted", e);
                Thread.currentThread().interrupt();
            }
        }
    }

    @Override
    public void someMethod() {
        log.info("Invoked");
    }

}
