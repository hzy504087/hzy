package com.leaf.handler;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Result implements Serializable {

    private int code;
    private String msg;
    private Object data;

    public static Result success(Object data) {
        return success(200, "操作成功", data);
    }

    public static Result success(int code, String msg, Object data) {
        Result result = new Result();
        result.setCode(code);
        result.setMsg(msg);
        result.setData(data);
        return result;
    }

    public static Result error(String msg) {
        return new Result(400, msg, null);
    }
    public static Result success(String msg) {
        return new Result(200, msg, null);
    }
    public static Result success(String msg,Object data) {
        return new Result(200, msg, data);
    }

    public static Result error(String msg, Object data) {
        return new Result(500,msg,data);
    }

}