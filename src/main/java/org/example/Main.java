package org.example;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.IpV4Packet;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.net.InetAddress;

public class Main {

    public static void main(String[] args) {

        JFrame frame = new JFrame("PCAP4J Packet Tool");
        frame.setSize(600, 400);
        frame.setLayout(null);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        JTextField textField = new JTextField();
        textField.setBounds(50, 50, 150, 30);
        frame.add(textField);

        JTextArea packetDisplay = new JTextArea();
        packetDisplay.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(packetDisplay);
        scrollPane.setBounds(50, 100, 500, 200);
        frame.add(scrollPane);

        JButton enter = new JButton("Enter Interface IP");
        enter.setBounds(210, 50, 150, 30);
        frame.add(enter);

        frame.setVisible(true);

        enter.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String ipOfInterface = textField.getText();

                try {
                    InetAddress addr = InetAddress.getByName(ipOfInterface);
                    PcapNetworkInterface nif = Pcaps.getDevByAddress(addr);

                    if (nif != null) {
                        System.out.println("Interface is valid! :D");
                        frame.getContentPane().setBackground(Color.GREEN);
                        
                        new Thread(() -> {
                            try {
                                int snapLen = 65536;
                                PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
                                int timeout = 10;
                                PcapHandle handle = nif.openLive(snapLen, mode, timeout);

                                while (true) {
                                    try {
                                        Packet packet = handle.getNextPacketEx();

                                        SwingUtilities.invokeLater(() -> {
                                            if (packet.contains(IpV4Packet.class)) {
                                                IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
                                                InetAddress srcAddr = ipV4Packet.getHeader().getSrcAddr();
                                                InetAddress dstAddr = ipV4Packet.getHeader().getDstAddr();

                                                packetDisplay.append("Captured Packet:\n");
                                                packetDisplay.append("Source Address: " + srcAddr + "\n");
                                                packetDisplay.append("Destination Address: " + dstAddr + "\n");
                                                packetDisplay.append(packet.toString() + "\n\n");
                                            } else {
                                                packetDisplay.append("Captured a non-IPv4 packet:\n");
                                                packetDisplay.append(packet.toString() + "\n\n");
                                            }
                                        });
                                    } catch (Exception ex) {
                                        packetDisplay.append("Error while capturing packets: " + ex.getMessage() + "\n");
                                    }
                                }
                            } catch (Exception ex) {
                                packetDisplay.append("Error while setting up packet capture: " + ex.getMessage() + "\n");
                            }
                        }).start();

                    } else {
                        System.out.println("Wrong interface :(");
                        frame.getContentPane().setBackground(Color.RED);
                        packetDisplay.setText("Invalid network interface.");
                    }
                } catch (IOException | PcapNativeException exception) {
                    System.out.println("Error:" + exception.getMessage());
                    frame.getContentPane().setBackground(Color.RED);
                    packetDisplay.setText("Error: " + exception.getMessage());
                }
            }
        });
    }
}
