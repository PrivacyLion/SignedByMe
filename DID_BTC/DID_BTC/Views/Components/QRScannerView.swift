// QRScannerView.swift - QR Code Scanner
// SignedByMe iOS

import SwiftUI
import AVFoundation

struct QRScannerView: View {
    let onScan: (String) -> Void
    let onCancel: () -> Void
    
    @State private var isFlashOn = false
    @State private var cameraPermissionDenied = false
    
    var body: some View {
        ZStack {
            // Camera preview
            CameraPreview(onScan: onScan, isFlashOn: $isFlashOn)
                .ignoresSafeArea()
            
            // Overlay
            VStack {
                // Top bar
                HStack {
                    Button(action: onCancel) {
                        Image(systemName: "xmark")
                            .font(.title2)
                            .foregroundColor(.white)
                            .padding(12)
                            .background(Circle().fill(.ultraThinMaterial))
                    }
                    
                    Spacer()
                    
                    Button {
                        isFlashOn.toggle()
                    } label: {
                        Image(systemName: isFlashOn ? "bolt.fill" : "bolt.slash.fill")
                            .font(.title2)
                            .foregroundColor(.white)
                            .padding(12)
                            .background(Circle().fill(.ultraThinMaterial))
                    }
                }
                .padding()
                
                Spacer()
                
                // Scan area frame
                ZStack {
                    // Dimmed background
                    Rectangle()
                        .fill(.black.opacity(0.5))
                        .mask(
                            Rectangle()
                                .overlay(
                                    RoundedRectangle(cornerRadius: 20)
                                        .frame(width: 280, height: 280)
                                        .blendMode(.destinationOut)
                                )
                        )
                    
                    // Corner brackets
                    RoundedRectangle(cornerRadius: 20)
                        .stroke(Color.white, lineWidth: 3)
                        .frame(width: 280, height: 280)
                    
                    // Animated scan line
                    ScanLineView()
                        .frame(width: 260, height: 260)
                        .clipShape(RoundedRectangle(cornerRadius: 16))
                }
                
                Spacer()
                
                // Instructions
                Text("Point camera at SignedByMe QR code")
                    .font(.subheadline)
                    .foregroundColor(.white)
                    .padding()
                    .background(Capsule().fill(.ultraThinMaterial))
                    .padding(.bottom, 50)
            }
        }
        .alert("Camera Access Required", isPresented: $cameraPermissionDenied) {
            Button("Open Settings") {
                if let url = URL(string: UIApplication.openSettingsURLString) {
                    UIApplication.shared.open(url)
                }
            }
            Button("Cancel", role: .cancel) {
                onCancel()
            }
        } message: {
            Text("Please allow camera access in Settings to scan QR codes.")
        }
        .onAppear {
            checkCameraPermission()
        }
    }
    
    private func checkCameraPermission() {
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            break
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { granted in
                if !granted {
                    DispatchQueue.main.async {
                        cameraPermissionDenied = true
                    }
                }
            }
        case .denied, .restricted:
            cameraPermissionDenied = true
        @unknown default:
            break
        }
    }
}

// MARK: - Camera Preview

struct CameraPreview: UIViewRepresentable {
    let onScan: (String) -> Void
    @Binding var isFlashOn: Bool
    
    func makeUIView(context: Context) -> CameraPreviewView {
        let view = CameraPreviewView()
        view.delegate = context.coordinator
        return view
    }
    
    func updateUIView(_ uiView: CameraPreviewView, context: Context) {
        uiView.setFlash(isFlashOn)
    }
    
    func makeCoordinator() -> Coordinator {
        Coordinator(onScan: onScan)
    }
    
    class Coordinator: NSObject, CameraPreviewViewDelegate {
        let onScan: (String) -> Void
        var lastScannedCode: String?
        
        init(onScan: @escaping (String) -> Void) {
            self.onScan = onScan
        }
        
        func didScanCode(_ code: String) {
            // Debounce duplicate scans
            guard code != lastScannedCode else { return }
            lastScannedCode = code
            
            DispatchQueue.main.async {
                self.onScan(code)
            }
        }
    }
}

// MARK: - Camera Preview View (UIKit)

protocol CameraPreviewViewDelegate: AnyObject {
    func didScanCode(_ code: String)
}

class CameraPreviewView: UIView {
    weak var delegate: CameraPreviewViewDelegate?
    
    private var captureSession: AVCaptureSession?
    private var previewLayer: AVCaptureVideoPreviewLayer?
    
    override init(frame: CGRect) {
        super.init(frame: frame)
        setupCamera()
    }
    
    required init?(coder: NSCoder) {
        super.init(coder: coder)
        setupCamera()
    }
    
    override func layoutSubviews() {
        super.layoutSubviews()
        previewLayer?.frame = bounds
    }
    
    private func setupCamera() {
        let session = AVCaptureSession()
        captureSession = session
        
        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device) else {
            return
        }
        
        if session.canAddInput(input) {
            session.addInput(input)
        }
        
        let output = AVCaptureMetadataOutput()
        if session.canAddOutput(output) {
            session.addOutput(output)
            output.setMetadataObjectsDelegate(self, queue: .main)
            output.metadataObjectTypes = [.qr]
        }
        
        let preview = AVCaptureVideoPreviewLayer(session: session)
        preview.videoGravity = .resizeAspectFill
        layer.addSublayer(preview)
        previewLayer = preview
        
        DispatchQueue.global(qos: .userInitiated).async {
            session.startRunning()
        }
    }
    
    func setFlash(_ on: Bool) {
        guard let device = AVCaptureDevice.default(for: .video),
              device.hasTorch else { return }
        
        try? device.lockForConfiguration()
        device.torchMode = on ? .on : .off
        device.unlockForConfiguration()
    }
    
    deinit {
        captureSession?.stopRunning()
    }
}

extension CameraPreviewView: AVCaptureMetadataOutputObjectsDelegate {
    func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        guard let object = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              object.type == .qr,
              let code = object.stringValue else {
            return
        }
        
        // Haptic feedback
        let generator = UINotificationFeedbackGenerator()
        generator.notificationOccurred(.success)
        
        delegate?.didScanCode(code)
    }
}

// MARK: - Scan Line Animation

struct ScanLineView: View {
    @State private var offset: CGFloat = -100
    
    var body: some View {
        GeometryReader { geo in
            Rectangle()
                .fill(
                    LinearGradient(
                        colors: [.clear, .blue.opacity(0.5), .clear],
                        startPoint: .leading,
                        endPoint: .trailing
                    )
                )
                .frame(height: 2)
                .offset(y: offset)
                .onAppear {
                    withAnimation(
                        .easeInOut(duration: 2)
                        .repeatForever(autoreverses: true)
                    ) {
                        offset = geo.size.height - 2
                    }
                }
        }
    }
}

// MARK: - Preview

#Preview {
    QRScannerView(
        onScan: { code in print("Scanned: \(code)") },
        onCancel: { print("Cancelled") }
    )
}
