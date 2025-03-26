import SwiftUI

struct ContentView: View {
    var body: some View {
        VStack {
            Image(systemName: "network")
                .imageScale(.large)
                .foregroundStyle(.tint)
            Text("iOS interop client")
        }
        .padding()
    }
}

#Preview {
    ContentView()
}
