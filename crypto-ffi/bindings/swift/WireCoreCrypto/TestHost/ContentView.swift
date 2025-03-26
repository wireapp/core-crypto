import SwiftUI

struct ContentView: View {
    var body: some View {
        VStack {
            Image(systemName: "globe")
                .imageScale(.large)
                .foregroundStyle(.tint)
            Text("Test Host")
        }
        .padding()
    }
}

#Preview {
    ContentView()
}
