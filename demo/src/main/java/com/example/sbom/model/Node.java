package com.example.sbom.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Node {
    private String id;
    private String name;
    private double rank;

    public Node(String id) {
        this.id = id;
        this.name = null;
        this.rank = 0.0;
    }
}
