"use client";

import React, { useEffect, useRef, useState } from "react";
import jsQR from "jsqr";
import {
  QrCode,
  Camera,
  Upload,
  Search,
  AlertCircle,
  CheckCircle2,
  ExternalLink,
  Sparkles,
  ArrowRight,
  VideoOff,
  Radio,
} from "lucide-react";
import { getCustomApiHeaders, saveScanToHistory } from "@/lib/storage";
import { ScanResult, UrlScanResult } from "@/types/threat";
import { ScanningProgress } from "@/components/common/ScanningProgress";

interface QrScannerProps {
  onScanComplete: (result: ScanResult) => void;
}

export function QrScanner({ onScanComplete }: QrScannerProps) {
  const [mode, setMode] = useState<"image" | "camera">("image");
  const [decodedData, setDecodedData] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isScanningCamera, setIsScanningCamera] = useState(false);

  const videoRef = useRef<HTMLVideoElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animationFrameRef = useRef<number | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Stop camera when unmounting or switching modes
  useEffect(() => {
    return () => {
      stopCamera();
    };
  }, []);

  const stopCamera = () => {
    if (animationFrameRef.current) {
      cancelAnimationFrame(animationFrameRef.current);
      animationFrameRef.current = null;
    }
    if (videoRef.current && videoRef.current.srcObject) {
      const stream = videoRef.current.srcObject as MediaStream;
      stream.getTracks().forEach((track) => track.stop());
      videoRef.current.srcObject = null;
    }
    setIsScanningCamera(false);
  };

  const startCamera = async () => {
    setError(null);
    setDecodedData(null);
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: "environment" },
      });

      if (videoRef.current) {
        videoRef.current.srcObject = stream;
        videoRef.current.setAttribute("playsinline", "true");
        await videoRef.current.play();
        setIsScanningCamera(true);
        requestAnimationFrame(tickCamera);
      }
    } catch (err) {
      console.error("Camera access failed:", err);
      setError("Unable to access webcam. Please ensure camera permissions are granted or upload an image instead.");
    }
  };

  const tickCamera = () => {
    if (videoRef.current && videoRef.current.readyState === videoRef.current.HAVE_ENOUGH_DATA) {
      const canvas = canvasRef.current;
      if (canvas) {
        const ctx = canvas.getContext("2d");
        if (ctx) {
          canvas.height = videoRef.current.videoHeight;
          canvas.width = videoRef.current.videoWidth;
          ctx.drawImage(videoRef.current, 0, 0, canvas.width, canvas.height);

          const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
          const code = jsQR(imageData.data, imageData.width, imageData.height, {
            inversionAttempts: "dontInvert",
          });

          if (code && code.data) {
            setDecodedData(code.data);
            stopCamera();
            handleAnalyzeDecodedUrl(code.data);
            return;
          }
        }
      }
    }
    animationFrameRef.current = requestAnimationFrame(tickCamera);
  };

  const handleImageFile = (file: File) => {
    setError(null);
    setDecodedData(null);

    const reader = new FileReader();
    reader.onload = (e) => {
      const img = new Image();
      img.onload = () => {
        const canvas = document.createElement("canvas");
        const ctx = canvas.getContext("2d");
        if (!ctx) {
          setError("Failed to create canvas for image decoding.");
          return;
        }

        canvas.width = img.width;
        canvas.height = img.height;
        ctx.drawImage(img, 0, 0, img.width, img.height);

        const imageData = ctx.getImageData(0, 0, img.width, img.height);
        const code = jsQR(imageData.data, imageData.width, imageData.height);

        if (code && code.data) {
          setDecodedData(code.data);
          handleAnalyzeDecodedUrl(code.data);
        } else {
          setError("No QR code detected in this image. Please upload a clear QR code image.");
        }
      };
      img.src = e.target?.result as string;
    };
    reader.readAsDataURL(file);
  };

  const handleAnalyzeDecodedUrl = async (targetUrl: string) => {
    setLoading(true);
    setError(null);

    try {
      const customHeaders = getCustomApiHeaders();
      const res = await fetch("/api/scan/url", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...customHeaders,
        },
        body: JSON.stringify({ url: targetUrl }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to analyze extracted QR target.");
      }

      saveScanToHistory(data);
      onScanComplete(data as UrlScanResult);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Analysis failed";
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  // Demo sample QR generator
  const handleSampleQr = (sampleUrl: string) => {
    setDecodedData(sampleUrl);
    handleAnalyzeDecodedUrl(sampleUrl);
  };

  return (
    <div className="space-y-6">
      {/* Scanner Card */}
      <div className="soc-card p-6 md:p-8 rounded-xl border border-soc-border relative overflow-hidden">
        <div className="flex items-center justify-between gap-4 mb-6">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-soc-dark border border-soc-border text-soc-accent">
              <QrCode className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white">QR Code Threat Scanner</h2>
              <p className="text-xs text-gray-400">
                Decode QR codes client-side from an image or live webcam, extract the embedded link, and analyze for malicious payloads.
              </p>
            </div>
          </div>

          {/* Mode Switcher */}
          <div className="flex items-center bg-soc-dark p-1 rounded-lg border border-soc-border text-xs font-mono">
            <button
              onClick={() => {
                stopCamera();
                setMode("image");
              }}
              className={`px-3 py-1.5 rounded flex items-center gap-1.5 transition-colors ${
                mode === "image" ? "bg-soc-accent text-soc-darkest font-semibold" : "text-gray-400 hover:text-white"
              }`}
            >
              <Upload className="w-3.5 h-3.5" />
              <span>Image Upload</span>
            </button>
            <button
              onClick={() => {
                setMode("camera");
                startCamera();
              }}
              className={`px-3 py-1.5 rounded flex items-center gap-1.5 transition-colors ${
                mode === "camera" ? "bg-soc-accent text-soc-darkest font-semibold" : "text-gray-400 hover:text-white"
              }`}
            >
              <Camera className="w-3.5 h-3.5" />
              <span>Live Camera</span>
            </button>
          </div>
        </div>

        {/* Mode: Image Upload */}
        {mode === "image" && (
          <div
            onDragOver={(e) => e.preventDefault()}
            onDrop={(e) => {
              e.preventDefault();
              if (e.dataTransfer.files?.[0]) handleImageFile(e.dataTransfer.files[0]);
            }}
            onClick={() => fileInputRef.current?.click()}
            className="border-2 border-dashed border-soc-border/80 hover:border-soc-accent/60 rounded-xl p-8 text-center cursor-pointer transition-all bg-soc-darker/50 hover:bg-soc-dark/50 group"
          >
            <input
              ref={fileInputRef}
              type="file"
              accept="image/*"
              className="hidden"
              onChange={(e) => {
                if (e.target.files?.[0]) handleImageFile(e.target.files[0]);
              }}
            />
            <div className="flex flex-col items-center justify-center gap-3">
              <div className="w-14 h-14 rounded-full bg-soc-dark border border-soc-border flex items-center justify-center group-hover:scale-110 group-hover:border-soc-accent/40 transition-all">
                <QrCode className="w-7 h-7 text-soc-accent" />
              </div>
              <div>
                <p className="text-sm font-semibold text-white">
                  Drop a QR code screenshot/image here, or <span className="text-soc-accent underline">browse</span>
                </p>
                <p className="text-xs text-gray-500 mt-1">PNG, JPG, WEBP, or SVG</p>
              </div>
            </div>
          </div>
        )}

        {/* Mode: Live Camera */}
        {mode === "camera" && (
          <div className="relative rounded-xl overflow-hidden bg-soc-darkest border border-soc-border p-4 flex flex-col items-center justify-center">
            <video ref={videoRef} className="max-w-md w-full rounded-lg border border-soc-border shadow-2xl" />
            <canvas ref={canvasRef} className="hidden" />

            {/* Target Reticle Overlay */}
            <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
              <div className="w-48 h-48 border-2 border-soc-accent/80 rounded-lg relative">
                <div className="absolute -top-1 -left-1 w-4 h-4 border-t-2 border-l-2 border-soc-accent" />
                <div className="absolute -top-1 -right-1 w-4 h-4 border-t-2 border-r-2 border-soc-accent" />
                <div className="absolute -bottom-1 -left-1 w-4 h-4 border-b-2 border-l-2 border-soc-accent" />
                <div className="absolute -bottom-1 -right-1 w-4 h-4 border-b-2 border-r-2 border-soc-accent" />
                <div className="absolute inset-x-0 top-1/2 h-0.5 bg-soc-accent/50 animate-pulse" />
              </div>
            </div>

            <div className="mt-3 flex items-center gap-3 z-10">
              <span className="flex items-center gap-1.5 text-xs font-mono text-soc-accent">
                <Radio className="w-3 h-3 animate-pulse" />
                Align QR code in view finder
              </span>
              <button
                onClick={stopCamera}
                className="px-3 py-1 text-xs font-mono rounded bg-soc-dark hover:bg-soc-border border border-soc-border text-gray-300 flex items-center gap-1"
              >
                <VideoOff className="w-3 h-3" />
                Stop
              </button>
            </div>
          </div>
        )}

        {/* Decoded QR Content Pill */}
        {decodedData && (
          <div className="mt-4 p-4 rounded-lg bg-soc-darker border border-soc-border flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div className="min-w-0">
              <div className="text-xs text-gray-400 font-mono flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                Decoded QR Payload:
              </div>
              <div className="text-xs md:text-sm font-mono text-white font-semibold truncate select-all mt-0.5">
                {decodedData}
              </div>
            </div>

            <button
              onClick={() => handleAnalyzeDecodedUrl(decodedData)}
              disabled={loading}
              className="px-4 py-2 rounded-lg bg-soc-accent hover:bg-emerald-400 text-soc-darkest font-semibold text-xs font-mono flex items-center justify-center gap-1.5 transition-all flex-shrink-0"
            >
              <Search className="w-3.5 h-3.5" />
              <span>{loading ? "Analyzing..." : "Re-Scan Link"}</span>
            </button>
          </div>
        )}

        {/* Quick Demo Samples */}
        <div className="flex flex-wrap items-center gap-2 mt-4 pt-2 border-t border-soc-border/40">
          <span className="text-xs text-gray-400 font-mono flex items-center gap-1">
            <Sparkles className="w-3 h-3 text-amber-400" />
            Test Samples:
          </span>
          <button
            type="button"
            onClick={() => handleSampleQr("http://secure-update-paypal-verify-account.net/login")}
            disabled={loading}
            className="text-xs font-mono px-2.5 py-1 rounded bg-soc-dark/70 hover:bg-soc-border/60 text-gray-300 border border-soc-border/60 transition-colors flex items-center gap-1"
          >
            <span>Simulate QR with Phishing Payload</span>
            <ArrowRight className="w-3 h-3 text-gray-500" />
          </button>
          <button
            type="button"
            onClick={() => handleSampleQr("https://www.github.com")}
            disabled={loading}
            className="text-xs font-mono px-2.5 py-1 rounded bg-soc-dark/70 hover:bg-soc-border/60 text-gray-300 border border-soc-border/60 transition-colors flex items-center gap-1"
          >
            <span>Simulate QR with Safe Target</span>
            <ArrowRight className="w-3 h-3 text-gray-500" />
          </button>
        </div>

        {/* Error Alert */}
        {error && (
          <div className="mt-4 p-3.5 rounded-lg bg-red-950/40 border border-red-500/40 text-red-400 text-xs font-mono flex items-start gap-2.5">
            <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* Live Scanning Stepper */}
      {loading && <ScanningProgress scanType="qr" target={decodedData || "QR Code"} />}
    </div>
  );
}
