/*
 * Copyright 2020-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nctu.winlab.ProxyArp;

import com.google.common.collect.ImmutableSet;
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

import org.onlab.packet.Ethernet;
import org.onlab.packet.ICMP;
import org.onlab.packet.IPv4;
import org.onlab.packet.MacAddress;
import org.onlab.packet.IpAddress;
import org.onlab.packet.IpAddress.Version;
import org.onlab.packet.ARP;

import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.event.Event;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.Link;
import org.onosproject.net.Path;
import org.onosproject.net.PortNumber;
import org.onosproject.net.host.HostService;
import org.onosproject.net.topology.TopologyService;

import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.ForwardingObjective;

import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.DefaultOutboundPacket;

import org.onosproject.net.edge.EdgePortEvent;
import org.onosproject.net.edge.EdgePortListener;
import org.onosproject.net.edge.EdgePortService;

import java.util.Dictionary;
import java.util.Properties;

import static org.onlab.util.Tools.get;
import com.google.common.collect.Maps;
import java.util.Map;
import java.util.HashMap;
import java.util.Iterator;
// import javafx.util.Pair;
import java.nio.ByteBuffer;
/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true,
           service = {SomeInterface.class},
           property = {
               "someProperty=Some Default String Value",
           })

public class AppComponent implements SomeInterface {

    public class Pair{
        private PortNumber port;
        private DeviceId id;
        public Pair(DeviceId id,PortNumber port) {
          this.id = id;
          this.port = port;
        }
        public PortNumber getport() { return port; }
        public DeviceId getid() { return id; }
    }

    private final Logger log = LoggerFactory.getLogger(getClass());

    /** Some configurable property. */
    private String someProperty;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    // @Reference(cardinality = ReferenceCardinality.MANDATORY)
    // protected FlowRuleService flowRuleService;

    // @Reference(cardinality = ReferenceCardinality.MANDATORY)
    // protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected TopologyService topologyService;    

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected EdgePortService edgeService;

    protected Map<IpAddress, MacAddress> ip_mac_table = Maps.newConcurrentMap();
    protected Map<IpAddress, DeviceId> ip_id_table = Maps.newConcurrentMap();
    protected Map<IpAddress, Pair> port_table = Maps.newConcurrentMap();
    private ApplicationId appId;
    private PacketProcessor processor;

    @Activate
    protected void activate() {
        cfgService.registerProperties(getClass());
        appId = coreService.registerApplication("nctu.winlab.ProxyArp");

        //edgeService.addListener(edgeListener);
        //edgeService.getEdgePoints().forEach(this::addDefault);

        processor = new ArpPacketProcessor();
        packetService.addProcessor(processor, PacketProcessor.director(2));
        packetService.requestPackets(DefaultTrafficSelector.builder()
            .matchEthType(Ethernet.TYPE_ARP).build(), PacketPriority.REACTIVE, appId);
        //log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        cfgService.unregisterProperties(getClass(), false);
        packetService.removeProcessor(processor);
        //flowRuleService.removeFlowRulesById(appId);
        processor = null;
        log.info("Stopped");
    }

    @Modified
    public void modified(ComponentContext context) {
        Dictionary<?, ?> properties = context != null ? context.getProperties() : new Properties();
        if (context != null) {
            someProperty = get(properties, "someProperty");
        }
        log.info("Reconfigured");
    }

    private class ArpPacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext pc) {
            InboundPacket pkt = pc.inPacket();
            Ethernet ethPkt = pkt.parsed();
            if (ethPkt == null) {
                return ;
            }
            if (ethPkt.getEtherType() == Ethernet.TYPE_ARP) {
                handleArp(pc, ethPkt);
            } 
        }
        private void handleArp(PacketContext pc, Ethernet ethPkt){
            InboundPacket pkt = pc.inPacket();
            MacAddress src = ethPkt.getSourceMAC();
            MacAddress dst = ethPkt.getDestinationMAC();
            ConnectPoint cp = pkt.receivedFrom();
            DeviceId device = cp.deviceId();
            PortNumber inport = cp.port();

            MacAddress flood = MacAddress.valueOf("FF:FF:FF:FF:FF:FF");
            ARP arpPkt = (ARP) ethPkt.getPayload();
            IpAddress srcIp = IpAddress.valueOf(IpAddress.Version.valueOf("INET"), arpPkt.getSenderProtocolAddress());
            IpAddress dstIp = IpAddress.valueOf(IpAddress.Version.valueOf("INET"), arpPkt.getTargetProtocolAddress());
            /*Table Learning*/

            Pair src_pair = new Pair (device,inport);
            
            if(!ip_mac_table.containsKey(srcIp)){
                ip_mac_table.put(srcIp, src);
                log.info("Ip to MAC table add:"+srcIp+" "+src);
            }
            if(!ip_id_table.containsKey(srcIp)){
                ip_id_table.put(srcIp, device);
                log.info("Ip to DeviceID table add:"+srcIp+" "+device);
            }
            if(!port_table.containsKey(srcIp)){
                port_table.put(srcIp, src_pair);
                log.info("Port table add"+srcIp+" "+device+" "+inport);
            }
            /*arp request*/
            if(arpPkt.getOpCode() == ARP.OP_REQUEST){ //(short)1
                if(dst.equals(flood)){
                    if(ip_mac_table.containsKey(dstIp)){ /*send arp reply directly*/
                        log.info("MacDst found in Ip to Mac table,then controller proxy arp");
                        MacAddress dstMac = ip_mac_table.get(dstIp);
                        Ethernet arpReply = ARP.buildArpReply(dstIp.getIp4Address(), dstMac, ethPkt);
                        TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(inport).build();
                        OutboundPacket packet = new DefaultOutboundPacket(device, treatment, ByteBuffer.wrap(arpReply.serialize()));
                        packetService.emit(packet);
                    }//log.info("Destination Mac found in IpAddress-macAddress-table");
                    else{
                        log.info("MacDst not found in Ip to Mac table,so FLOOD");
                        flood(ethPkt,cp);
                        //getEdgePoints();
                    }
                }
                else{ /*when timeover: arp request will send again*/
                    log.info("ARP Request with MacDst Not Flooding,device:"+device+" src:"+src+" dst:"+dst);
                    MacAddress outMac = ip_mac_table.get(dstIp);
                    Ethernet arpReply = ARP.buildArpReply(dstIp.getIp4Address(), outMac, ethPkt);
                    TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(inport).build();
                    OutboundPacket packet = new DefaultOutboundPacket(device, treatment, ByteBuffer.wrap(arpReply.serialize()));
                    packetService.emit(packet);
                }
            }
            else if(arpPkt.getOpCode() ==  ARP.OP_REPLY){//(short)2
                //log.info("ARP Reply Packet,then controller proxy arp");
                DeviceId device_out = port_table.get(dstIp).getid();
                PortNumber outport = port_table.get(dstIp).getport();

                log.info("Proxy ARP Reply Packet:"+dstIp+" "+device_out+" "+outport);
                TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(outport).build();
                OutboundPacket packet = new DefaultOutboundPacket(device_out, treatment, ByteBuffer.wrap(ethPkt.duplicate().serialize()));
                packetService.emit(packet);
            }
        }
        private void packetOut(PacketContext context, PortNumber portNumber) {
            context.treatmentBuilder().setOutput(portNumber);
            context.send();
        }

        private void flood(Ethernet request, ConnectPoint inPort){ //(PacketContext context) 
            // context.treatmentBuilder().setOutput(PortNumber.FLOOD);
            // context.send();
            ARP arpPkt = (ARP) request.getPayload();
            TrafficTreatment.Builder builder = null;
            ByteBuffer buf = ByteBuffer.wrap(request.serialize());

            for (ConnectPoint connectPoint : edgeService.getEdgePoints()) {
                // if (isOutsidePort(connectPoint) || connectPoint.equals(inPort)) {
                //     continue;
                // }
                log.info("Flood edge port:"+connectPoint+" with:"+arpPkt.getSenderProtocolAddress());
                builder = DefaultTrafficTreatment.builder();
                builder.setOutput(connectPoint.port());
                packetService.emit(new DefaultOutboundPacket(connectPoint.deviceId(),builder.build(), buf));
            }
        }
    }

    @Override
    public void someMethod() {
        log.info("Invoked");
    }

}
