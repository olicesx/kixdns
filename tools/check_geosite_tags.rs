use std::env;
use std::fs;

fn parse_varint(data: &[u8], pos: &mut usize) -> anyhow::Result<usize> {
    let mut result = 0usize;
    let mut shift = 0;

    loop {
        if *pos >= data.len() {
            anyhow::bail!("unexpected end of file");
        }
        let byte = data[*pos];
        *pos += 1;
        result |= ((byte & 0x7F) as usize) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
    }

    Ok(result)
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let dat_path = if args.len() > 1 {
        &args[1]
    } else {
        "data/geosite.dat"
    };

    println!("检查 GeoSite 数据文件: {}", dat_path);
    println!("============================================================");

    let content = fs::read(dat_path)?;

    println!("[INFO] 文件大小: {} 字节\n", content.len());

    let mut pos = 0;
    let mut all_tags = Vec::new();
    let mut gfw_tags = Vec::new();
    let mut github_tags = Vec::new();

    while pos < content.len() {
        if pos >= content.len() {
            break;
        }

        let field_tag = content[pos];
        pos += 1;

        let entry_len = parse_varint(&content, &mut pos)?;

        if pos + entry_len > content.len() {
            break;
        }

        let entry_end = pos + entry_len;

        // field_tag = 0x0A 表示 GeoSite 条目
        if field_tag == 0x0A {
            let mut tag = String::new();
            let mut has_github = false;

            // 保存entry起始位置
            let entry_start = pos;

            // 解析 GeoSite 条目内容
            while pos < entry_end {
                let inner_tag = content[pos];
                pos += 1;

                let inner_len = parse_varint(&content, &mut pos)?;

                if pos + inner_len > entry_end {
                    break;
                }

                match inner_tag {
                    0x0A => {
                        // tag 字段
                        if let Ok(tag_str) = std::str::from_utf8(&content[pos..pos + inner_len]) {
                            tag = tag_str.to_string();
                        }
                        pos += inner_len;
                    }
                    0x12 => {
                        // domains 字段 - 检查是否包含 github
                        let domains_data = &content[pos..pos + inner_len];
                        if domains_data.iter().any(|&b| b.eq_ignore_ascii_case(&b'g'))
                            && domains_data.iter().any(|&b| b.eq_ignore_ascii_case(&b'i'))
                            && domains_data.iter().any(|&b| b.eq_ignore_ascii_case(&b't'))
                            && domains_data.iter().any(|&b| b.eq_ignore_ascii_case(&b'h'))
                            && domains_data.iter().any(|&b| b.eq_ignore_ascii_case(&b'u'))
                            && domains_data.iter().any(|&b| b.eq_ignore_ascii_case(&b'b'))
                        {
                            // 简单检查 - 更准确的应该完整解析
                            if let Ok(data_str) = std::str::from_utf8(domains_data) {
                                if data_str.to_lowercase().contains("github") {
                                    has_github = true;
                                }
                            }
                        }
                        pos += inner_len;
                    }
                    _ => {
                        pos += inner_len;
                    }
                }
            }

            if !tag.is_empty() {
                let tag_lower = tag.to_lowercase();
                all_tags.push(tag.clone());

                if tag_lower.contains("gfw") {
                    gfw_tags.push((tag.clone(), has_github));
                }

                if tag_lower.contains("github") {
                    github_tags.push(tag.clone());
                }
            }
        } else {
            pos = entry_end;
        }
    }

    // 输出结果
    println!("[STATS] 统计信息:");
    println!("   总共找到 {} 个标签\n", all_tags.len());

    if !gfw_tags.is_empty() {
        println!("[FOUND] 找到 {} 个 GFW 相关标签:", gfw_tags.len());
        for (tag, has_github) in &gfw_tags {
            if *has_github {
                println!("   - {} [包含 github]", tag);
            } else {
                println!("   - {} [不包含 github]", tag);
            }
        }
    } else {
        println!("[NOT FOUND] 未找到包含 'gfw' 的标签");
    }

    println!();

    if !github_tags.is_empty() {
        println!("[FOUND] 找到 {} 个 github 相关标签:", github_tags.len());
        for tag in &github_tags {
            println!("   - {}", tag);
        }
    } else {
        println!("[NOT FOUND] 未找到包含 'github' 的标签");
    }

    println!();
    println!("[LIST] 所有标签列表 (前50个):");
    for (i, tag) in all_tags.iter().take(50).enumerate() {
        println!("   {:3}. {}", i + 1, tag);
    }

    println!();
    println!("[HINT] 如果需要查找特定标签，使用:");
    println!("   cargo run --example check_geosite_tags <path-to-dat> | grep <keyword>");

    Ok(())
}
