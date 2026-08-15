import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ThreatVigil | Threat Intelligence & Malware Scanner",
  description: "Enterprise multi-source cyber threat intelligence scanner. Analyze URLs, IP addresses, file hashes, binary uploads, and QR codes across 70+ security vendors with VirusTotal, AbuseIPDB, and Google Safe Browsing.",
  keywords: ["Threat Intelligence", "VirusTotal", "AbuseIPDB", "Google Safe Browsing", "Malware Scanner", "Cybersecurity", "SOC Analyst"],
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="antialiased bg-soc-darkest text-gray-100 min-h-screen">
        {children}
      </body>
    </html>
  );
}
