package org.example;

import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.IpV4Packet;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.Inet4Address;
import java.net.InetAddress;

public class Main {
    public static void main(String[] args) throws Exception {

        JFrame frame = new JFrame("PCAP4J Packet Tool");
        frame.setSize(400, 400);
        frame.setLayout(null); // Set layout to null for absolute positioning
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE); // Ensure the application exits on close


        JTextField textField = new JTextField();
        textField.setBounds(50, 50, 150, 30);
        frame.add(textField);


        JTextArea packetDisplay = new JTextArea();
        packetDisplay.setBounds(50, 100, 500, 400);
        packetDisplay.setEditable(false);
        frame.add(packetDisplay);




        JButton enter = new JButton("Enter Interface IP");
        enter.setBounds(210, 50, 100, 30);
        frame.add(enter);

        enter.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String ipOfInterface = textField.getText();
                System.out.println("Entered IP: " + ipOfInterface);

                try {
                    InetAddress addr = InetAddress.getByName(ipOfInterface);
                    PcapNetworkInterface nif = Pcaps.getDevByAddress(addr);

                    if (nif != null) {
                        System.out.println("Interface is valid! :D");
                        frame.setBackground(Color.GREEN);


                        // part that analyzes network packets
                        try {
                            int snapLen = 65536; // Capture the maximum number of bytes per packet
                            PromiscuousMode mode = PromiscuousMode.PROMISCUOUS; // Capture all packets
                            int timeout = 10; // Timeout in milliseconds
                            PcapHandle handle = nif.openLive(snapLen, mode, timeout);

                            Packet packet = handle.getNextPacketEx();
                            handle.close();

                            // Check if the packet is an IPv4 packet
                            IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
                            if (ipV4Packet != null) {
                                Inet4Address srcAddr = ipV4Packet.getHeader().getSrcAddr();
                                System.out.println("Source IP Address: " + srcAddr);
                            } else {
                                System.out.println("Captured packet is not an IPv4 packet.");
                            }
                        } catch (Exception ex) {
                            System.out.println("Error while analyzing packets: " + ex.getMessage());
                        }

                    } else {
                        System.out.println("Invalid interface IP");
                        frame.setBackground(Color.RED);
                    }
                } catch (Exception ex) {
                    System.out.println("Error: " + ex.getMessage());
                }
            }
        });

        // Ensure the frame is properly laid out
        frame.setVisible(true);
    }
}
