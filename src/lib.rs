use pyo3::prelude::*;
use etherparse::PacketHeaders;

#[pyfunction]
fn parse_packet(data: &[u8]) -> PyResult<String> {
    match PacketHeaders::from_ethernet_slice(data) {
        Ok(headers) =>{
            let mut out = String::new();

            if let Some(link) = headers.link {
                out.push_str(&format!("Ethernet Header: {:?}\n", link));
            }

            if let Some(ip) = headers.ip {
                out.push_str(&format!("IP Header: {:?}\n", ip));
            }

            if let Some(transport) = headers.transport {
                out.push_str(&format!("Transport Header: {:?}\n", transport));
            }

            Ok(out)
        },
        Err(e) => {
            Err(pyo3::exceptions::PyValueError::new_err(format!("Failed to parse packet: {}", e)))
        }
    }
}

#[pymodule]
fn pytherparse(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(parse_packet, m)?)?;
    Ok(())
}