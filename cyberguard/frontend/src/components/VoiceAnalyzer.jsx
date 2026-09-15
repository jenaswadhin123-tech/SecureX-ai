import React, { useState, useRef } from "react";
import { Mic, UploadCloud, ShieldCheck, Loader2, X, FileAudio } from "lucide-react";
import { analyzeVoice } from "../services/api";

const ACCEPTED_EXTS = /\.(wav|mp3|ogg|m4a|webm|flac)$/i;
const MAX_SIZE_MB = 25;

export default function VoiceAnalyzer({ onEventGenerated }) {
  const [audioFile, setAudioFile] = useState(null);
  const [audioUrl, setAudioUrl] = useState(null);
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const fileInputRef = useRef(null);

  const handleFile = (file) => {
    if (!file) return;
    if (!file.type.startsWith("audio/") && !ACCEPTED_EXTS.test(file.name)) {
      setError("Unsupported file type. Please upload a WAV, MP3, OGG, M4A, FLAC or WebM audio file.");
      return;
    }
    if (file.size > MAX_SIZE_MB * 1024 * 1024) {
      setError("File too large. Maximum allowed size is " + MAX_SIZE_MB + " MB.");
      return;
    }
    setError("");
    setResult(null);
    if (audioUrl) URL.revokeObjectURL(audioUrl);
    setAudioFile(file);
    setAudioUrl(URL.createObjectURL(file));
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragging(false);
    handleFile(e.dataTransfer.files[0]);
  };

  const handleAnalyze = async () => {
    if (!audioFile) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const res = await analyzeVoice(audioFile);
      setResult(res);
      if (onEventGenerated) onEventGenerated();
    } catch (err) {
      setError(err.response?.data?.detail || "Voice analysis failed. Ensure the backend is running.");
    } finally {
      setLoading(false);
    }
  };

  const clearFile = () => {
    setAudioFile(null);
    if (audioUrl) URL.revokeObjectURL(audioUrl);
    setAudioUrl(null);
    setResult(null);
    setError("");
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  const getVerdictStyle = (level) => {
    switch (level?.toUpperCase()) {
      case "CRITICAL": return "border-rose-500/40 bg-rose-500/10 text-rose-400";
      case "HIGH":     return "border-orange-500/40 bg-orange-500/10 text-orange-400";
      case "MEDIUM":   return "border-amber-500/40 bg-amber-500/10 text-amber-400";
      case "LOW":      return "border-blue-500/40 bg-blue-500/10 text-blue-400";
      default:         return "border-emerald-500/40 bg-emerald-500/10 text-emerald-400";
    }
  };

  const getVoiceVerdictColor = (verdict) => {
    if (!verdict) return "text-secondaryText";
    if (verdict.includes("AI") || verdict.includes("GENERATED")) return "text-rose-400";
    if (verdict.includes("HUMAN")) return "text-emerald-400";
    return "text-amber-400";
  };

  const formatBytes = (bytes) => {
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / (1024 * 1024)).toFixed(2) + " MB";
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="bg-cardBg border border-cardBorder p-6 rounded-xl">
        <div className="flex items-center space-x-3 mb-5">
          <div className="p-2 bg-purple-500/10 text-purple-400 rounded-lg border border-purple-500/20">
            <Mic className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-lg font-bold text-white">AI Voice and Vishing Detector</h3>
            <p className="text-xs text-secondaryText">Upload a voice recording to detect AI-synthesized speech, deepfakes, or vishing attempts.</p>
          </div>
        </div>

        <div
          onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={handleDrop}
          onClick={() => !audioFile && fileInputRef.current?.click()}
          className={"relative border-2 border-dashed rounded-xl transition-all " + (dragging ? "border-purple-500 bg-purple-500/10 " : "border-cardBorder hover:border-accentBlue/50 hover:bg-accentBlue/5 ") + (!audioFile ? "cursor-pointer" : "")}
        >
          <input ref={fileInputRef} type="file" accept="audio/*" className="hidden" onChange={(e) => handleFile(e.target.files[0])} />
          {!audioFile ? (
            <div className="flex flex-col items-center justify-center py-12 px-6 text-center">
              <UploadCloud className="w-10 h-10 text-secondaryText mb-3" />
              <p className="text-sm font-medium text-white">Drop audio file here, or <span className="text-accentBlue underline">browse</span></p>
              <p className="text-xs text-secondaryText mt-1">Supports WAV, MP3, OGG, M4A, FLAC, WebM</p>
            </div>
          ) : (
            <div className="p-4 space-y-3">
              <div className="flex items-center space-x-3">
                <div className="p-2 bg-purple-500/10 text-purple-400 rounded-lg border border-purple-500/20">
                  <FileAudio className="w-5 h-5" />
                </div>
                <div>
                  <p className="text-sm font-medium text-white truncate max-w-xs">{audioFile.name}</p>
                  <p className="text-xs text-secondaryText">{formatBytes(audioFile.size)}</p>
                </div>
              </div>
              {audioUrl && <audio controls src={audioUrl} className="w-full h-8" />}
            </div>
          )}
          {audioFile && (
            <button onClick={(e) => { e.stopPropagation(); clearFile(); }} className="absolute top-3 right-3 p-1.5 bg-darkBg border border-cardBorder hover:border-rose-500/40 hover:text-rose-400 text-secondaryText rounded-lg transition-colors">
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        <div className="mt-4 flex flex-col sm:flex-row items-start sm:items-center gap-3">
          <button onClick={handleAnalyze} disabled={loading || !audioFile} className="px-6 py-2.5 bg-purple-600 hover:bg-purple-700 disabled:opacity-50 text-white font-medium text-sm rounded-lg transition-colors flex items-center space-x-2">
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Mic className="w-4 h-4" />}
            <span>{loading ? "Analyzing Audio..." : "Analyze Voice Recording"}</span>
          </button>
          <p className="text-xs text-secondaryText">Checks: AI synthesis, vishing intent, acoustic anomalies, scam transcript patterns.</p>
        </div>

        {error && <div className="mt-4 p-3 bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs rounded-lg">{error}</div>}
      </div>

      {result && (
        <div className="bg-cardBg border border-cardBorder p-6 rounded-xl space-y-6">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-4 border-b border-cardBorder">
            <div>
              <span className="text-xs font-mono text-secondaryText uppercase tracking-wider">Voice Threat Verdict</span>
              <h4 className="text-xl font-bold text-white mt-1 flex items-center gap-3">
                Risk Level:
                <span className={"px-3 py-1 rounded-full border text-xs font-extrabold " + getVerdictStyle(result.risk_level)}>
                  {result.risk_level || "SAFE"} ({result.risk_score ?? 0}/100)
                </span>
              </h4>
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[
              { label: "Voice Verdict", value: result.voice_verdict || "N/A", cls: getVoiceVerdictColor(result.voice_verdict) },
              { label: "AI Confidence", value: result.voice_confidence != null ? result.voice_confidence + "%" : "N/A", cls: "text-white" },
              { label: "Scam Score", value: result.scam_score != null ? result.scam_score + "/100" : "N/A", cls: result.scam_score >= 70 ? "text-rose-400" : "text-amber-400" },
              { label: "Category", value: result.threat_category || "N/A", cls: "text-accentBlue" },
            ].map(({ label, value, cls }) => (
              <div key={label} className="bg-darkBg border border-cardBorder rounded-lg p-3">
                <p className="text-xs text-secondaryText uppercase tracking-wider mb-1">{label}</p>
                <p className={"text-sm font-bold font-mono " + cls}>{value}</p>
              </div>
            ))}
          </div>

          {result.transcript && (
            <div>
              <h5 className="text-xs font-semibold text-secondaryText uppercase tracking-wider mb-2">Audio Transcript</h5>
              <div className="bg-darkBg border border-cardBorder rounded-lg p-4 text-xs font-mono text-primaryText leading-relaxed italic">"{result.transcript}"</div>
            </div>
          )}

          {result.evidence && result.evidence.length > 0 ? (
            <div>
              <h5 className="text-xs font-semibold text-secondaryText uppercase tracking-wider mb-2">Acoustic Evidence</h5>
              <div className="divide-y divide-cardBorder border border-cardBorder rounded-lg overflow-hidden bg-darkBg">
                {result.evidence.map((item, i) => (
                  <div key={i} className="px-4 py-2.5 flex items-center justify-between text-xs font-mono">
                    <span className="text-rose-400 font-semibold">{item.name}</span>
                    <div className="flex items-center gap-3">
                      <div className="w-28 bg-cardBorder rounded-full h-1.5">
                        <div className="bg-rose-500 h-1.5 rounded-full" style={{ width: Math.min(100, item.value) + "%" }} />
                      </div>
                      <span className="text-secondaryText w-12 text-right">+{item.value}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="p-3 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs rounded-lg flex items-center gap-2">
              <ShieldCheck className="w-4 h-4" />
              <span>No suspicious acoustic evidence detected. Voice appears to be genuine human speech.</span>
            </div>
          )}

          {result.acoustic_features && Object.keys(result.acoustic_features).length > 0 && (
            <div>
              <h5 className="text-xs font-semibold text-secondaryText uppercase tracking-wider mb-2">Raw Acoustic Features</h5>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                {Object.entries(result.acoustic_features).map(([key, val]) => (
                  <div key={key} className="bg-darkBg border border-cardBorder rounded-lg px-3 py-2">
                    <p className="text-[10px] text-secondaryText uppercase tracking-wide">{key.replace(/_/g, " ")}</p>
                    <p className="text-xs text-white font-mono mt-0.5">{typeof val === "number" ? val.toFixed(2) : String(val)}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {result.recommendations && result.recommendations.length > 0 && (
            <div>
              <h5 className="text-xs font-semibold text-secondaryText uppercase tracking-wider mb-2">Security Recommendations</h5>
              <ul className="space-y-1.5 text-xs text-primaryText">
                {result.recommendations.map((rec, i) => (
                  <li key={i} className="flex items-center space-x-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-purple-400 shrink-0" />
                    <span>{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

        </div>
      )}
    </div>
  );
}
