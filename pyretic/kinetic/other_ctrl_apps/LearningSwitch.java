public class LearningSwitch
    implements IFloodlightModule, ILearningSwitchService, IOFMessageListener {
    protected static Logger log = LoggerFactory.getLogger(LearningSwitch.class);
    protected IFloodlightProviderService floodlightProvider;
    protected ICounterStoreService counterStore;
    protected IRestApiService restApi;
    protected Map<IOFSwitch, Map<MacVlanPair,Short>> macVlanToSwitchPortMap;
    public static final int LEARNING_SWITCH_APP_ID = 1;
    public static final int APP_ID_BITS = 12;
    public static final int APP_ID_SHIFT = (64 - APP_ID_BITS);
    public static final long LEARNING_SWITCH_COOKIE = (long) (LEARNING_SWITCH_APP_ID & ((1 << APP_ID_BITS) - 1)) << APP_ID_SHIFT;
    protected static short FLOWMOD_DEFAULT_IDLE_TIMEOUT = 5; // in seconds
    protected static short FLOWMOD_DEFAULT_HARD_TIMEOUT = 0; // infinite
    protected static short FLOWMOD_PRIORITY = 100;
    protected static final int MAX_MACS_PER_SWITCH  = 1000;
    public void setFloodlightProvider(IFloodlightProviderService floodlightProvider) {
        this.floodlightProvider = floodlightProvider;
    }
    @Override
    public String getName() {
        return "learningswitch";
    }
    protected void addToPortMap(IOFSwitch sw, long mac, short vlan, short portVal) {
        Map<MacVlanPair,Short> swMap = macVlanToSwitchPortMap.get(sw);
        if (vlan == (short) 0xffff) {
            vlan = 0;
        }

        if (swMap == null) {
            swMap = Collections.synchronizedMap(new LRULinkedHashMap<MacVlanPair,Short>(MAX_MACS_PER_SWITCH));
            macVlanToSwitchPortMap.put(sw, swMap);
        }
        swMap.put(new MacVlanPair(mac, vlan), portVal);
    }

    protected void removeFromPortMap(IOFSwitch sw, long mac, short vlan) {
        if (vlan == (short) 0xffff) {
            vlan = 0;
        }
        Map<MacVlanPair,Short> swMap = macVlanToSwitchPortMap.get(sw);
        if (swMap != null)
            swMap.remove(new MacVlanPair(mac, vlan));
    }

    public Short getFromPortMap(IOFSwitch sw, long mac, short vlan) {
        if (vlan == (short) 0xffff) {
            vlan = 0;
        }
        Map<MacVlanPair,Short> swMap = macVlanToSwitchPortMap.get(sw);
        if (swMap != null)
            return swMap.get(new MacVlanPair(mac, vlan));

        return null;
    }

    public void clearLearnedTable() {
        macVlanToSwitchPortMap.clear();
    }

    public void clearLearnedTable(IOFSwitch sw) {
        Map<MacVlanPair, Short> swMap = macVlanToSwitchPortMap.get(sw);
        if (swMap != null)
            swMap.clear();
    }

    @Override
    public synchronized Map<IOFSwitch, Map<MacVlanPair,Short>> getTable() {
        return macVlanToSwitchPortMap;
    }

    private void writeFlowMod(IOFSwitch sw, short command, int bufferId,
            OFMatch match, short outPort) {
        OFFlowMod flowMod = (OFFlowMod) floodlightProvider.getOFMessageFactory().getMessage(OFType.FLOW_MOD);
        flowMod.setMatch(match);
        flowMod.setCookie(LearningSwitch.LEARNING_SWITCH_COOKIE);
        flowMod.setCommand(command);
        flowMod.setIdleTimeout(LearningSwitch.FLOWMOD_DEFAULT_IDLE_TIMEOUT);
        flowMod.setHardTimeout(LearningSwitch.FLOWMOD_DEFAULT_HARD_TIMEOUT);
        flowMod.setPriority(LearningSwitch.FLOWMOD_PRIORITY);
        flowMod.setBufferId(bufferId);
        flowMod.setOutPort((command == OFFlowMod.OFPFC_DELETE) ? outPort : OFPort.OFPP_NONE.getValue());
        flowMod.setFlags((command == OFFlowMod.OFPFC_DELETE) ? 0 : (short) (1 << 0)); // OFPFF_SEND_FLOW_REM

        flowMod.setActions(Arrays.asList((OFAction) new OFActionOutput(outPort, (short) 0xffff)));
        flowMod.setLength((short) (OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH));

        if (log.isTraceEnabled()) {
            log.trace("{} {} flow mod {}",
                      new Object[]{ sw, (command == OFFlowMod.OFPFC_DELETE) ? "deleting" : "adding", flowMod });
        }

        counterStore.updatePktOutFMCounterStoreLocal(sw, flowMod);

        try {
            sw.write(flowMod, null);
        } catch (IOException e) {
            log.error("Failed to write {} to switch {}", new Object[]{ flowMod, sw }, e);
        }
    }

    private void pushPacket(IOFSwitch sw, OFMatch match, OFPacketIn pi, short outport) {
        if (pi == null) {
            return;
        }

        if (pi.getInPort() == outport) {
            if (log.isDebugEnabled()) {
                log.debug("Attempting to do packet-out to the same " +
                          "interface as packet-in. Dropping packet. " +
                          " SrcSwitch={}, match = {}, pi={}",
                          new Object[]{sw, match, pi});
                return;
            }
        }

        if (log.isTraceEnabled()) {
            log.trace("PacketOut srcSwitch={} match={} pi={}",
                      new Object[] {sw, match, pi});
        }

        OFPacketOut po =
                (OFPacketOut) floodlightProvider.getOFMessageFactory()
                                                .getMessage(OFType.PACKET_OUT);

        List<OFAction> actions = new ArrayList<OFAction>();
        actions.add(new OFActionOutput(outport, (short) 0xffff));

        po.setActions(actions)
          .setActionsLength((short) OFActionOutput.MINIMUM_LENGTH);
        short poLength =
                (short) (po.getActionsLength() + OFPacketOut.MINIMUM_LENGTH);

        if (sw.getBuffers() == 0) {
            pi.setBufferId(OFPacketOut.BUFFER_ID_NONE);
            po.setBufferId(OFPacketOut.BUFFER_ID_NONE);
        } else {
            po.setBufferId(pi.getBufferId());
        }

        po.setInPort(pi.getInPort());

        if (pi.getBufferId() == OFPacketOut.BUFFER_ID_NONE) {
            byte[] packetData = pi.getPacketData();
            poLength += packetData.length;
            po.setPacketData(packetData);
        }

        po.setLength(poLength);

        try {
            counterStore.updatePktOutFMCounterStoreLocal(sw, po);
            sw.write(po, null);
        } catch (IOException e) {
            log.error("Failure writing packet out", e);
        }
    }


    private void writePacketOutForPacketIn(IOFSwitch sw,
                                          OFPacketIn packetInMessage,
                                          short egressPort) {
        OFPacketOut packetOutMessage = (OFPacketOut) floodlightProvider.getOFMessageFactory().getMessage(OFType.PACKET_OUT);
        short packetOutLength = (short)OFPacketOut.MINIMUM_LENGTH; // starting length

        packetOutMessage.setBufferId(packetInMessage.getBufferId());
        packetOutMessage.setInPort(packetInMessage.getInPort());
        packetOutMessage.setActionsLength((short)OFActionOutput.MINIMUM_LENGTH);
        packetOutLength += OFActionOutput.MINIMUM_LENGTH;

        List<OFAction> actions = new ArrayList<OFAction>(1);
        actions.add(new OFActionOutput(egressPort, (short) 0));
        packetOutMessage.setActions(actions);

        if (packetInMessage.getBufferId() == OFPacketOut.BUFFER_ID_NONE) {
            byte[] packetData = packetInMessage.getPacketData();
            packetOutMessage.setPacketData(packetData);
            packetOutLength += (short)packetData.length;
        }

        packetOutMessage.setLength(packetOutLength);

        try {
            counterStore.updatePktOutFMCounterStoreLocal(sw, packetOutMessage);
            sw.write(packetOutMessage, null);
        } catch (IOException e) {
            log.error("Failed to write {} to switch {}: {}", new Object[]{ packetOutMessage, sw, e });
        }
    }
    private Command processPacketInMessage(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {
        OFMatch match = new OFMatch();
        match.loadFromPacket(pi.getPacketData(), pi.getInPort());
        Long sourceMac = Ethernet.toLong(match.getDataLayerSource());
        Long destMac = Ethernet.toLong(match.getDataLayerDestination());
        Short vlan = match.getDataLayerVirtualLan();
        if ((destMac & 0xfffffffffff0L) == 0x0180c2000000L) {
            if (log.isTraceEnabled()) {
                log.trace("ignoring packet addressed to 802.1D/Q reserved addr: switch {} vlan {} dest MAC {}",
                          new Object[]{ sw, vlan, HexString.toHexString(destMac) });
            }
            return Command.STOP;
        }
        if ((sourceMac & 0x010000000000L) == 0) {
            this.addToPortMap(sw, sourceMac, vlan, pi.getInPort());
        }

        Short outPort = getFromPortMap(sw, destMac, vlan);
        if (outPort == null) {
            this.writePacketOutForPacketIn(sw, pi, OFPort.OFPP_FLOOD.getValue());
        } else if (outPort == match.getInputPort()) {
            log.trace("ignoring packet that arrived on same port as learned destination:"
                    + " switch {} vlan {} dest MAC {} port {}",
                    new Object[]{ sw, vlan, HexString.toHexString(destMac), outPort });
        } else {
            match.setWildcards(((Integer)sw.getAttribute(IOFSwitch.PROP_FASTWILDCARDS)).intValue()
                    & ~OFMatch.OFPFW_IN_PORT
                    & ~OFMatch.OFPFW_DL_VLAN & ~OFMatch.OFPFW_DL_SRC & ~OFMatch.OFPFW_DL_DST
                    & ~OFMatch.OFPFW_NW_SRC_MASK & ~OFMatch.OFPFW_NW_DST_MASK);
            this.pushPacket(sw, match, pi, outPort);
            this.writeFlowMod(sw, OFFlowMod.OFPFC_ADD, OFPacketOut.BUFFER_ID_NONE, match, outPort);
            if (LEARNING_SWITCH_REVERSE_FLOW) {
                this.writeFlowMod(sw, OFFlowMod.OFPFC_ADD, -1, match.clone()
                    .setDataLayerSource(match.getDataLayerDestination())
                    .setDataLayerDestination(match.getDataLayerSource())
                    .setNetworkSource(match.getNetworkDestination())
                    .setNetworkDestination(match.getNetworkSource())
                    .setTransportSource(match.getTransportDestination())
                    .setTransportDestination(match.getTransportSource())
                    .setInputPort(outPort),
                    match.getInputPort());
            }
        }
        return Command.CONTINUE;
    }

    private Command processFlowRemovedMessage(IOFSwitch sw, OFFlowRemoved flowRemovedMessage) {
        if (flowRemovedMessage.getCookie() != LearningSwitch.LEARNING_SWITCH_COOKIE) {
            return Command.CONTINUE;
        }
        if (log.isTraceEnabled()) {
            log.trace("{} flow entry removed {}", sw, flowRemovedMessage);
        }
        OFMatch match = flowRemovedMessage.getMatch();
        this.removeFromPortMap(sw, Ethernet.toLong(match.getDataLayerSource()),
            match.getDataLayerVirtualLan());

        this.writeFlowMod(sw, OFFlowMod.OFPFC_DELETE, -1, match.clone()
                .setWildcards(((Integer)sw.getAttribute(IOFSwitch.PROP_FASTWILDCARDS)).intValue()
                        & ~OFMatch.OFPFW_DL_VLAN & ~OFMatch.OFPFW_DL_SRC & ~OFMatch.OFPFW_DL_DST
                        & ~OFMatch.OFPFW_NW_SRC_MASK & ~OFMatch.OFPFW_NW_DST_MASK)
                .setDataLayerSource(match.getDataLayerDestination())
                .setDataLayerDestination(match.getDataLayerSource())
                .setNetworkSource(match.getNetworkDestination())
                .setNetworkDestination(match.getNetworkSource())
                .setTransportSource(match.getTransportDestination())
                .setTransportDestination(match.getTransportSource()),
                match.getInputPort());
        return Command.CONTINUE;
    }


    @Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        switch (msg.getType()) {
            case PACKET_IN:
                return this.processPacketInMessage(sw, (OFPacketIn) msg, cntx);
            case FLOW_REMOVED:
                return this.processFlowRemovedMessage(sw, (OFFlowRemoved) msg);
            case ERROR:
                log.info("received an error {} from switch {}", msg, sw);
                return Command.CONTINUE;
            default:
                break;
        }
        log.error("received an unexpected message {} from switch {}", msg, sw);
        return Command.CONTINUE;
    }

    @Override
    public boolean isCallbackOrderingPrereq(OFType type, String name) {
        return false;
    }

    @Override
    public boolean isCallbackOrderingPostreq(OFType type, String name) {
        return false;
    }


    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        Collection<Class<? extends IFloodlightService>> l =
                new ArrayList<Class<? extends IFloodlightService>>();
        l.add(ILearningSwitchService.class);
        return l;
    }

    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService>
            getServiceImpls() {
        Map<Class<? extends IFloodlightService>,
            IFloodlightService> m =
                new HashMap<Class<? extends IFloodlightService>,
                    IFloodlightService>();
        m.put(ILearningSwitchService.class, this);
        return m;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>>
            getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> l =
                new ArrayList<Class<? extends IFloodlightService>>();
        l.add(IFloodlightProviderService.class);
        l.add(ICounterStoreService.class);
        l.add(IRestApiService.class);
        return l;
    }

    @Override
    public void init(FloodlightModuleContext context)
            throws FloodlightModuleException {
        macVlanToSwitchPortMap =
                new ConcurrentHashMap<IOFSwitch, Map<MacVlanPair,Short>>();
        floodlightProvider =
                context.getServiceImpl(IFloodlightProviderService.class);
        counterStore =
                context.getServiceImpl(ICounterStoreService.class);
        restApi =
                context.getServiceImpl(IRestApiService.class);
    }

    @Override
    public void startUp(FloodlightModuleContext context) {
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
        floodlightProvider.addOFMessageListener(OFType.FLOW_REMOVED, this);
        floodlightProvider.addOFMessageListener(OFType.ERROR, this);
        restApi.addRestletRoutable(new LearningSwitchWebRoutable());

        Map<String, String> configOptions = context.getConfigParams(this);
        try {
            String idleTimeout = configOptions.get("idletimeout");
            if (idleTimeout != null) {
                FLOWMOD_DEFAULT_IDLE_TIMEOUT = Short.parseShort(idleTimeout);
            }
        } catch (NumberFormatException e) {
            log.warn("Error parsing flow idle timeout, " +
                     "using default of {} seconds",
                     FLOWMOD_DEFAULT_IDLE_TIMEOUT);
        }
        try {
            String hardTimeout = configOptions.get("hardtimeout");
            if (hardTimeout != null) {
                FLOWMOD_DEFAULT_HARD_TIMEOUT = Short.parseShort(hardTimeout);
            }
        } catch (NumberFormatException e) {
            log.warn("Error parsing flow hard timeout, " +
                     "using default of {} seconds",
                     FLOWMOD_DEFAULT_HARD_TIMEOUT);
        }
        try {
            String priority = configOptions.get("priority");
            if (priority != null) {
                FLOWMOD_PRIORITY = Short.parseShort(priority);
            }
        } catch (NumberFormatException e) {
            log.warn("Error parsing flow priority, " +
                     "using default of {}",
                     FLOWMOD_PRIORITY);
        }
        log.debug("FlowMod idle timeout set to {} seconds",
                  FLOWMOD_DEFAULT_IDLE_TIMEOUT);
        log.debug("FlowMod hard timeout set to {} seconds",
                  FLOWMOD_DEFAULT_HARD_TIMEOUT);
        log.debug("FlowMod priority set to {}",
                FLOWMOD_PRIORITY);
    }
}
