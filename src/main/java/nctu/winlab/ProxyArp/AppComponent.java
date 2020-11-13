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
//start
import java.nio.ByteBuffer;
import com.google.common.collect.Maps;
import com.google.common.collect.ImmutableSet;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.TpPort;
import org.onlab.packet.UDP;
import org.onlab.packet.Ethernet;
import org.onlab.packet.MacAddress;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.ARP;

import org.onosproject.net.ConnectPoint;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.Path;
import org.onosproject.net.PortNumber;

import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.DefaultOutboundPacket;

import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRuleService;

import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;

import org.onosproject.net.host.HostService;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.net.topology.TopologyService;
import org.onosproject.net.edge.EdgePortService;
import org.onosproject.net.edge.EdgePortListener;
import java.util.Set;
import java.util.HashMap;

//end


import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.config.ConfigFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Dictionary;
import java.util.Properties;
import java.util.Map;
import java.util.Optional;

import static org.onlab.util.Tools.get;

/** Sample Network Configuration Service Application */
@Component(immediate = true,
			service = {SomeInterface.class},
			property ={
				"someProperty=Some Default String value",
			})
public class AppComponent implements SomeInterface{

  private final Logger log = LoggerFactory.getLogger(getClass());

	private ApplicationId appId;
	private String someProperty;

	@Reference(cardinality = ReferenceCardinality.MANDATORY)
	protected ComponentConfigService cfgService;

	@Reference(cardinality = ReferenceCardinality.MANDATORY)
	protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;


    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected TopologyService topologyService;

	@Reference(cardinality = ReferenceCardinality.MANDATORY)
	protected EdgePortService edgePortService;

    private DHCPRoutingProcessor processor = new DHCPRoutingProcessor();

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;
    protected FlowObjectiveService flowObjectiveService2;


    private static ConnectPoint deviceConnectPoint = null;

	protected Map<Ip4Address,MacAddress> ARPTable = Maps.newConcurrentMap();

  @Activate
  protected void activate() {
  	cfgService.registerProperties(getClass());
    appId = coreService.getAppId("nctu.winlab.ProxyArp");
	packetService.addProcessor(processor,PacketProcessor.director(2));
    log.info("Started");
  }
  @Deactivate
  protected void deactivate() {
	packetService.removeProcessor(processor);
	processor = null;
    cfgService.unregisterProperties(getClass(),false);
    log.info("Stopped");
  }

	private class DHCPRoutingProcessor implements PacketProcessor{
		@Override
		public void process(PacketContext context){
			if(context.isHandled()){
				return;
			}

			lookUpTableAndAction(context);
		}


	}
	
	private void lookUpTableAndAction(PacketContext packetContext){
		Ethernet ethPkt = packetContext.inPacket().parsed();
		ARP arpPkt = (ARP)ethPkt.getPayload();
		MacAddress srcMAC = ethPkt.getSourceMAC();
		Ip4Address srcIP = Ip4Address.valueOf(arpPkt.getSenderProtocolAddress());
		Ip4Address tarIP = Ip4Address.valueOf(arpPkt.getTargetProtocolAddress());
		//put requester information into table
		ARPTable.put(srcIP,srcMAC);
		//arp request
		if(arpPkt.getOpCode() == 1){
			if(ARPTable.get(tarIP) == null){
				log.info("TABLE MISS. Send request to edge ports");
				floodEdge(ethPkt);
			}
			else{
				MacAddress wantMAC = ARPTable.get(tarIP);
				String msg = "TABLE HIT. Requested MAC = "+wantMAC.toString();
				log.info(msg);
				//packet out
				Ethernet replyEthPkt = ARP.buildArpReply(tarIP,wantMAC,ethPkt);
				sendArpReply(packetContext,replyEthPkt);
			}
		}
		//arp reply
		else if(arpPkt.getOpCode() == 2){
			MacAddress wantMAC = srcMAC;
			MacAddress tarMAC = MacAddress.valueOf(arpPkt.getTargetHardwareAddress());
			String msg = "RECV REPLY. Request MAC = "+wantMAC.toString();
			log.info(msg);
			//find target device
			HostId dstId = HostId.hostId(tarMAC);
			Host dst = hostService.getHost(dstId);
			if (dstId == null){
				log.info("dstId null");
			}
			if(dst == null){
				log.info("dst null");
			}
			if( ethPkt == null){
				log.info("ethpkt null");
			}
			targetArpReply(dst,ethPkt);


		}
	}
	private void targetArpReply(Host dst,Ethernet reply){
		if(reply != null){
			TrafficTreatment.Builder builder = DefaultTrafficTreatment.builder();
			builder.setOutput(dst.location().port());
			packetService.emit(new DefaultOutboundPacket(dst.location().deviceId(),
				builder.build(),ByteBuffer.wrap(reply.serialize())));
		}
			
	}
	private void sendArpReply(PacketContext pkt,Ethernet reply){
		if(reply != null){
			TrafficTreatment.Builder builder = DefaultTrafficTreatment.builder();
			ConnectPoint sourcePoint = pkt.inPacket().receivedFrom();
			builder.setOutput(sourcePoint.port());
			pkt.block();
			packetService.emit(new DefaultOutboundPacket(sourcePoint.deviceId(),
				builder.build(),ByteBuffer.wrap(reply.serialize())));
		}
	}
	private void PacketOut(PacketContext pktContext,PortNumber port){
		pktContext.treatmentBuilder().setOutput(port);
		pktContext.send();
	}
	private void floodFunc(PacketContext pktContext){
		PacketOut(pktContext,PortNumber.FLOOD);
	}
	private void floodEdge(Ethernet ethPkt){
		if( ethPkt != null){
			TrafficTreatment.Builder builder = DefaultTrafficTreatment.builder();
			edgePortService.getEdgePoints().forEach(s->log.info(s.toString()));

			edgePortService.getEdgePoints().forEach(s->packetService.emit(packet(builder,s,ByteBuffer.wrap(ethPkt.serialize()))));
//			Optional<TrafficTreatment> builder = Optional.ofNullable(null);
//			edgePortService.emitPacket(ByteBuffer.wrap(ethPkt.serialize()),builder);
		}

	}
	private DefaultOutboundPacket packet(TrafficTreatment.Builder builder,ConnectPoint point,ByteBuffer data){
		builder.setOutput(point.port());
		return new DefaultOutboundPacket(point.deviceId(),builder.build(),data);

	}




	private void findPathAndFlowmod(PacketContext context, InboundPacket pkt, Ethernet ethPkt,Host dst,boolean isBroadcast){
		log.info("start find path and flowmod");
		if( isBroadcast == true){
			log.info("broadcast here");
			log.info(pkt.receivedFrom().deviceId().toString());
			log.info(deviceConnectPoint.deviceId().toString());
			if(pkt.receivedFrom().deviceId().equals(deviceConnectPoint.deviceId())){
				log.info("destination is on same switch");;
				installRule(context,deviceConnectPoint.port());
				return;
			}
			log.info("not at same swwwitch");
		}
		else{
			if( pkt.receivedFrom().deviceId().equals(dst.location().deviceId())){
				log.info("not  broadcast heere");
				//check although at same device,but  the inport and outport are  distinct
				if(!context.inPacket().receivedFrom().port().equals(dst.location().port())){
					log.info("UUnicast message is on same switch");
					installRule(context,dst.location().port());
				}
				return;
			}
		}

//find the path to destinationn
		Set<Path> paths;
		if(isBroadcast == true){
			//is brooadcast
			log.info("is broadcast and try to find pathh");
			paths  = topologyService.getPaths(topologyService.currentTopology(),
						pkt.receivedFrom().deviceId(),
						deviceConnectPoint.deviceId());
		}
		else{
			//is not broadcast
			log.info("is not broadcast and try to find path");
			paths  = topologyService.getPaths(topologyService.currentTopology(),
						pkt.receivedFrom().deviceId(),
						dst.location().deviceId());
		
		}

		//if no path?
		//pick a ppath
		log.info("before find  interest");
		Path intPath=null;//interest path
		for(Path path:paths){
			if(!path.src().port().equals(pkt.receivedFrom().port())){
				intPath = path;
				log.info("find the Path");
				break;
			}
//			log.info("fid int looop");
		}
		log.info("before install rule");
		installRule(context,intPath.src().port());
///		log.info("ater insstall  rule");
	}

	private void installRule(PacketContext context,PortNumber portNumber){
		//use to create matching field
		TrafficSelector.Builder  selectorBuilder = DefaultTrafficSelector.builder();
		InboundPacket pkt = context.inPacket();
		Ethernet ethPkt  = pkt.parsed();

		if(ethPkt.isBroadcast()){
			selectorBuilder.matchEthType(Ethernet.TYPE_IPV4)
				.matchIPProtocol(IPv4.PROTOCOL_UDP)
				.matchUdpDst(TpPort.tpPort(UDP.DHCP_SERVER_PORT))
				.matchUdpSrc(TpPort.tpPort(UDP.DHCP_CLIENT_PORT));
		}
		else{
			selectorBuilder.matchEthType(Ethernet.TYPE_IPV4)
				.matchEthDst(ethPkt.getDestinationMAC())
				.matchEthSrc(ethPkt.getSourceMAC());

		}
		//use  to create action
		TrafficTreatment treatmentBuild = DefaultTrafficTreatment.builder()
			.setOutput(portNumber).build();

		//to install the flow mod
		ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
			.withSelector(selectorBuilder.build())
			.withTreatment(treatmentBuild)
			.withPriority(50000)
			.withFlag(ForwardingObjective.Flag.VERSATILE)
			.fromApp(appId)
			.makeTemporary(20)
			.add();
		flowObjectiveService.forward(pkt.receivedFrom().deviceId(),forwardingObjective);
		//packetout
		context.treatmentBuilder().setOutput(portNumber);
		context.send();

	}
    @Modified
	public void modified(ComponentContext context) {
	   	Dictionary<?, ?> properties = context != null ? context.getProperties() : new Properties();
		if (context != null) {
		    someProperty = get(properties, "someProperty");
		}
        log.info("Reconfigured");
	}


	@Override
	public void someMethod(){
		log.info("Invoked");
	}
}
