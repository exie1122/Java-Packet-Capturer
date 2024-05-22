package org.example;

import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.IpV4Packet;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.Scanner;

import javax.swing.*;


public class Main {
    public static void main(String[] args) throws Exception {

        JFrame frame = new JFrame("PCAP4J Test");
        frame.setSize(400, 400);
        frame.setLayout(null);
        frame.setVisible(true);
        frame.setResizable(false);

        JTextField textField = new JTextField();
        textField.setBounds(50, 50, 150, 30);
        frame.add(textField);


        JButton enter = new JButton("Enter");
        frame.add(enter);

        enter.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                System.out.println(textField.getText());
            }
        });




        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter your Wifi Interface's IP");
        String ipOfInterface = scanner.nextLine();

        InetAddress addr = InetAddress.getByName(ipOfInterface);
        PcapNetworkInterface nif = Pcaps.getDevByAddress(addr);


        if (nif != null) {
            System.out.println("Interface is valid! :D");
        } else {
            System.out.println("Invalid interface IP");
            return;
        }

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
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
}
