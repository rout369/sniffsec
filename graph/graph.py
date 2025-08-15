import json
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import plotly.io as pio
import logging

def generate_graph_from_json(json_file):
    """Generate interactive 3D-effect graphs from JSON: a 2D pie chart, 3D scatter plot, and always-visible IP bar chart with toggle."""
    try:
        import math
        with open(json_file, 'r') as f:
            data = json.load(f)

        ip_counts = data.get('ip_counter', {})
        ip_addresses = list(ip_counts.keys()) if ip_counts else ['No IPs']
        ip_values = list(ip_counts.values()) if ip_counts else [0]
        protocol_counts = data.get('protocol_counter', {})
        labels = list(protocol_counts.keys()) if protocol_counts else ['No Protocols']
        sizes = list(protocol_counts.values()) if protocol_counts else [0]

        # Debug prints
        print(f"IP Counts: {ip_counts}")
        print(f"Protocol Counts: {protocol_counts}")
        print(f"Labels: {labels}")
        print(f"Sizes: {sizes}")

        # Create a subplot with three cells
        fig = make_subplots(
            rows=1, cols=3,
            specs=[[{'type': 'pie'}, {'type': 'scene'}, {'type': 'xy'}]],
            subplot_titles=("Protocol Distribution", "3D Protocol Distribution", "IP Distribution")
        )

        # 2D Pie Chart
        if labels and sizes:
            fig.add_trace(
                go.Pie(
                    labels=labels,
                    values=sizes,
                    hole=0.4,
                    textinfo='label+percent',
                    marker=dict(colors=['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728'], line=dict(color='black', width=2)),
                    hoverinfo='label+value+percent',
                    textposition='inside',
                    pull=[0.1] * len(labels),
                    rotation=90,
                    visible=True
                ),
                row=1, col=1
            )
        else:
            fig.add_trace(go.Pie(labels=['No Data'], values=[1], textinfo='label', visible=True), row=1, col=1)

        # 3D Scatter Plot for Pie
        if labels and sizes:
            theta = [i * 360 / len(labels) for i in range(len(labels))]  # Angles for each protocol
            x_coords = [1.0 * math.cos(math.radians(t)) for t in theta]  # Fixed radius of 1.0
            y_coords = [1.0 * math.sin(math.radians(t)) for t in theta]
            z_coords = sizes
            print(f"Debug - Coordinates: {list(zip(labels, x_coords, y_coords, z_coords))}")
            fig.add_trace(
                go.Scatter3d(
                    x=x_coords,
                    y=y_coords,
                    z=z_coords,
                    text=labels,
                    mode='markers+text',
                    marker=dict(size=12, color=sizes, colorscale='Viridis', opacity=0.8),
                    name='3D View',
                    visible=False
                ),
                row=1, col=2
            )
        else:
            fig.add_trace(go.Scatter3d(x=[0], y=[0], z=[0], text=['No Data'], mode='markers+text', visible=False), row=1, col=2)

        # IP Bar Chart (always visible)
        if ip_addresses and ip_values:
            fig.add_trace(
                go.Bar(
                    x=ip_addresses,
                    y=ip_values,
                    marker=dict(color='skyblue', line=dict(color='black', width=1.5), opacity=0.8),
                    hovertemplate='IP: %{x}<br>Count: %{y}',
                    name='IP Counts',
                    visible=True
                ),
                row=1, col=3
            )
        else:
            fig.add_trace(go.Bar(x=['No IPs'], y=[0], marker=dict(color='skyblue'), visible=True), row=1, col=3)

        # Update layout with toggle buttons for 2D and 3D only
        fig.update_layout(
            updatemenus=[
                dict(
                    type="buttons",
                    direction="left",
                    buttons=list([
                        dict(
                            args=[{"visible": [True, False, True]}, {"title": "Network Traffic Analysis (2D Pie View)"}],
                            label="2D Pie View",
                            method="update"
                        ),
                        dict(
                            args=[{"visible": [False, True, True]}, {"title": "Network Traffic Analysis (3D Scatter View)"}],
                            label="3D Scatter View",
                            method="update"
                        )
                    ]),
                    pad={"r": 10, "t": 10},
                    showactive=True,
                    x=0.11,
                    xanchor="left",
                    y=1.1,
                    yanchor="top"
                ),
            ],
            title="Network Traffic Analysis",
            showlegend=True,
            margin=dict(l=0, r=0, t=80, b=0),
            height=800,  # Increased height to accommodate three columns
            scene=dict(
                xaxis_title="Angular Position (X) - Represents the horizontal angle of each protocol",
                yaxis_title="Angular Position (Y) - Represents the vertical angle of each protocol",
                zaxis_title="Packet Count (Z) - Represents the number of packets for each protocol",
                aspectmode='cube'
            ),
            xaxis3=dict(title="IP Address"),  # Title for the bar chart x-axis
            yaxis3=dict(title="Packet Count")  # Title for the bar chart y-axis
        )

        # Save the interactive plot
        output_html = json_file.replace('.json', '_plot.html')
        pio.write_html(fig, file=output_html, auto_open=True)
        logging.info(f"Interactive graph saved to {output_html}")

    except Exception as e:
        logging.error(f"Failed to generate graph: {e}")