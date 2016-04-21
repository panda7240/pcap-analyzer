package com.sweet;


import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapHandle.TimestampPrecision;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.EOFException;
import java.util.concurrent.TimeoutException;

public class PcapAnalyzer {

    private static Logger logger = LoggerFactory.getLogger(PcapAnalyzer.class);

    private static final int COUNT = 5;

    private static final String PCAP_FILE_KEY
            = PcapAnalyzer.class.getName() + ".pcapFile";
    private static final String PCAP_FILE
            = System.getProperty(PCAP_FILE_KEY, "/Users/panda/abc.pcap");

    private PcapAnalyzer() {
    }

    public static void main(String[] args) throws PcapNativeException, NotOpenException {
        PcapHandle handle;
        try {
            handle = Pcaps.openOffline(PCAP_FILE, TimestampPrecision.NANO);
        } catch (PcapNativeException e) {
            handle = Pcaps.openOffline(PCAP_FILE);
        }

        for (int i = 0; i < COUNT; i++) {
            try {
                Packet packet = handle.getNextPacketEx();
                logger.info(handle.getTimestamp().toString());
                logger.info(packet.toString());
            } catch (TimeoutException e) {
            } catch (EOFException e) {
                System.out.println("EOF");
                break;
            }
        }

        handle.close();
    }
}