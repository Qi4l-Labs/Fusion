use screenshots::Screen;
use std::io::{Cursor, Error, ErrorKind};
use std::time::Instant;

pub async fn screenshot() -> Result<Vec<u8>, Error> {
    let start = Instant::now();
    // let screens = Screen::all().unwrap();

    // for screen in screens {
    //     println!("capturer {screen:?}");
    //     let mut image = screen.capture().unwrap();
    // }

    let screen = match Screen::from_point(0, 0) {
        Ok(s) => s,
        Err(e) => {
            return Err(Error::new(ErrorKind::Other, e));
        }
    };

    // TODO: When capturing on Linux, it leads the panic 'UnsupportedVersion' in `libwayshot-0.2.0`.
    let img = match screen.capture() {
        Ok(ib) => ib,
        Err(e) => {
            return Err(Error::new(ErrorKind::Other, e));
        }
    };

    let mut bytes: Vec<u8> = Vec::new();
    let _ = img.write_to(&mut Cursor::new(&mut bytes), screenshots::image::ImageOutputFormat::Png);

    Ok(bytes)
}