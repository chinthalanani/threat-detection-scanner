import { getApiKeys } from "@/lib/api-keys";
import { getDemoFileScan } from "@/lib/demo-data";
import { checkRateLimit } from "@/lib/rate-limiter";
import { NextRequest, NextResponse } from "next/server";

export async function POST(req: NextRequest) {
  try {
    const clientIp = req.headers.get("x-forwarded-for") || "local_client";
    const limit = checkRateLimit(`file_upload_${clientIp}`, 10, 60);
    if (!limit.allowed) {
      return NextResponse.json(
        { error: `Upload rate limit reached. Please wait ${limit.resetInSeconds}s before scanning another file.` },
        { status: 429 }
      );
    }

    const formData = await req.formData();
    const file = formData.get("file") as File | null;
    const clientHash = formData.get("hash") as string | null;

    if (!file) {
      return NextResponse.json({ error: "No file provided in form data." }, { status: 400 });
    }

    const fileName = file.name || "uploaded_file";
    const fileSize = file.size;
    const keys = getApiKeys(req);

    // If no VirusTotal key, return realistic demo data
    if (!keys.virusTotalKey) {
      const demoResult = getDemoFileScan(fileName, clientHash || "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", fileSize);
      return NextResponse.json(demoResult);
    }

    // Limit free upload size to 32MB
    if (fileSize > 32 * 1024 * 1024) {
      return NextResponse.json(
        { error: "File size exceeds 32MB free tier limit for VirusTotal API." },
        { status: 400 }
      );
    }

    // Prepare upload to VirusTotal v3
    const vtFormData = new FormData();
    vtFormData.append("file", file);

    const vtRes = await fetch("https://www.virustotal.com/api/v3/files", {
      method: "POST",
      headers: {
        "x-apikey": keys.virusTotalKey,
      },
      body: vtFormData,
    });

    if (!vtRes.ok) {
      const errText = await vtRes.text();
      throw new Error(`VirusTotal file upload failed (${vtRes.status}): ${errText}`);
    }

    const vtData = await vtRes.json();
    const analysisId = vtData?.data?.id;

    if (!analysisId) {
      throw new Error("VirusTotal did not return a valid analysis ID.");
    }

    return NextResponse.json({
      status: "queued",
      analysisId,
      fileName,
      fileSize,
      message: "File successfully queued for analysis. Polling for multi-engine verdict...",
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "File upload processing error";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
